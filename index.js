/**
 * Always-on Board — Host half (Windows port).
 *
 * Enumerates the background work declared on this machine — Windows Task
 * Scheduler tasks (the per-user and system equivalent of launchd jobs) and
 * Windows services (the system-daemon equivalent) — joins them with the
 * running-process snapshot, and serves one read-only JSON snapshot to the
 * Web client at /plugins/ops-board/state.json.
 *
 * Nothing here writes, starts, stops or restarts a task or service: the
 * board only reports. The snapshot shape, the notes system, the traffic
 * light classification and the web-server registration are unchanged from
 * the macOS original; only the collectors are Windows.
 */
import {collectProcesses, runPowerShell} from './processes.js'
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { homedir, hostname } from 'node:os'
import { dirname, join } from 'node:path'

export const name = 'ops-board'
export const inject = ['webServer']

const STATE_PATH = '/plugins/ops-board/state.json'
const CACHE_MS = 5000

/** The user-owned, hand-edited file behind the "what is this job?" line. */
const NOTES_PATH = join(homedir(), '.config', 'dsh-ops-board', 'notes.json')

/** Optional override file for our own inferred explanations. */
const AUTO_PATH = join(homedir(), '.config', 'dsh-ops-board', 'auto.json')

/**
 * Our own one-line explanations, written from each task and script,
 * deliberately not copied from the task's own documentation. A note in
 * notes.json always wins; an empty string here hides the inferred line.
 * (No shipped defaults on Windows: the macOS vendor list does not apply.)
 */
const AUTO_DEFAULTS = {}

/**
 * One PowerShell collection for both persistent sources:
 * MSFT_ScheduledTask rows (+ Get-ScheduledTaskInfo) and Win32_Service rows.
 * MSFT_ScheduledTask lives in root/Microsoft/Windows/TaskScheduler, NOT the
 * default root/cimv2 namespace — without -Namespace the query fails with
 * "Invalid class" and the tasks come back empty.
 * $ProgressPreference is silenced first: progress records surface as CLIXML
 * on stdout and would corrupt the JSON the client parses.
 */
export const TASKS_SCRIPT = `
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
function IsoOrNull($d) { if ($d -and $d.Year -gt 2000) { $d.ToString('o') } else { $null } }
function IsoOrNullStr($v) { if ($v -is [string]) { $v } else { $null } }
$tasks = Get-CimInstance -Namespace root/Microsoft/Windows/TaskScheduler -ClassName MSFT_ScheduledTask | ForEach-Object {
  $t = $_; $info = $null
  try { $info = $t | Get-ScheduledTaskInfo -ErrorAction Stop } catch {}
  $action = ($t.Actions | Where-Object { $_.Execute } | Select-Object -First 1)
  $reps = @()
  foreach ($tr in @($t.Triggers)) {
    if ($tr.Repetition -and $tr.Repetition.Interval -and $tr.Repetition.Interval -ne 'PT0S') {
      try { $ivSeconds = [Xml.XmlConvert]::ToTimeSpan($tr.Repetition.Interval).TotalSeconds } catch { $ivSeconds = $null }
      if ($ivSeconds) { $reps += [int]$ivSeconds }
    }
  }
  $repetitionSeconds = if ($reps.Count) { ($reps | Measure-Object -Minimum).Minimum } else { $null }
  $triggers = @()
  foreach ($tr in @($t.Triggers)) {
    $tt = @{CimClass=$tr.CimClass.CimClassName;Enabled=$tr.Enabled;StartBoundary=IsoOrNull $tr.StartBoundary;RepetitionInterval=IsoOrNullStr $tr.Repetition.Interval;RepetitionDuration=IsoOrNullStr $tr.Repetition.Duration}
    if ($tr.Repetition) { $tt.Repetition = @{Interval=IsoOrNullStr $tr.Repetition.Interval;Duration=IsoOrNullStr $tr.Repetition.Duration;StopAtDurationEnd=$tr.Repetition.StopAtDurationEnd;RestartOnFailure=$tr.Repetition.RestartOnFailure} }
    $triggers += $tt
  }
  $settings = @{}
  if ($t.Settings) {
    $settings = @{AllowHardTerminate=$t.Settings.AllowHardTerminate;DisallowStartIfOnBatteries=$t.Settings.DisallowStartIfOnBatteries;ExecutionTimeLimit=IsoOrNullStr $t.Settings.ExecutionTimeLimit;Hidden=$t.Settings.Hidden;MultipleInstances=$t.Settings.MultipleInstances.ToString();RestartCount=$t.Settings.RestartCount;RestartInterval=IsoOrNullStr $t.Settings.RestartInterval;RunOnlyIfNetworkAvailable=$t.Settings.RunOnlyIfNetworkAvailable;StartWhenAvailable=$t.Settings.StartWhenAvailable;StopIfGoingOnBatteries=$t.Settings.StopIfGoingOnBatteries;WakeToRun=$t.Settings.WakeToRun}
  }
  [pscustomobject]@{Path=$t.TaskPath;Name=$t.TaskName;State=[int]$t.State;Principal=$t.Principal;ActionExecute=IsoOrNullStr $action.Execute;ActionArguments=IsoOrNullStr $action.Arguments;ActionWorkingDirectory=IsoOrNullStr $action.WorkingDirectory;Triggers=$triggers;Settings=$settings;LastRunTime=IsoOrNull $(if ($info) { $info.LastRunTime } else { $null });LastTaskResult=if ($info) { $info.LastTaskResult } else { $null };NextRunTime=IsoOrNull $(if ($info) { $info.NextRunTime } else { $null });NumberOfMissedRuns=if ($info) { $info.NumberOfMissedRuns } else { $null };RepetitionSeconds=$repetitionSeconds}
}
$services = Get-CimInstance Win32_Service | ForEach-Object {
  [pscustomobject]@{Name=$_.Name;DisplayName=$_.DisplayName;State=$_.State;StartMode=$_.StartMode;StartName=$_.StartName;PathName=$_.PathName;ProcessId=$_.ProcessId;ExitCode=$_.ExitCode}
}
[pscustomobject]@{tasks=$tasks;services=$services} | ConvertTo-Json -Depth 4 -Compress
`

/** Map an MSFT_ScheduledTask row onto the launch-task shape the UI expects. */
export function parseWindowsTask(record, now = Date.now()) {
  const state = Number(record.State)
  const id = `${record.Path || '\\'}${record.Name || ''}`
  const rawTriggers = record.Triggers || []
  const triggers = rawTriggers.map(t => ({
    kind: t.CimClass || 'Trigger',
    enabled: t.Enabled !== false,
    startBoundary: t.StartBoundary || null,
    repetition: t.Repetition || null,
    restartOnFailure: Boolean(t.Repetition?.RestartOnFailure),
  }))
  const repetitionSeconds = Number(record.RepetitionSeconds) || null
  const lastTaskResult = record.LastTaskResult === null || record.LastTaskResult === undefined
    ? null : Number(record.LastTaskResult)
  const lastRunTime = record.LastRunTime || null
  const missedRuns = Number(record.NumberOfMissedRuns) || 0
  const systemTask = /^(?:\\Microsoft\\Windows\\)/i.test(id)
    || /^(?:NT AUTHORITY\\SYSTEM|NT AUTHORITY\\LOCALSERVICE|NT AUTHORITY\\NETWORKSERVICE|NT AUTHORITY\\SERVICE)$/i.test(String(record.Principal?.UserId || ''))
  const enabledTriggers = triggers.filter(t => t.enabled)
  const runAtLoad = enabledTriggers.some(t =>
    /^(MSFT_TaskLogonTrigger|MSFT_TaskBootTrigger)$/.test(t.kind))
  // Task Scheduler has no always-on semantic: RestartOnFailure /
  // RestartCount only retry a failed run, so they must NOT map to KeepAlive
  // (doing so flagged every idle task with restart settings as failed).
  // Only Auto services are keep-alive.
  const keepAlive = false
  // Staleness is judged against the schedule: a repetition interval first,
  // else the trigger's own cadence (daily/weekly/monthly). Without this,
  // every task without a repetition interval would warn after 30 hours.
  const scheduleSeconds = enabledTriggers.reduce((best, t) => {
    const seconds = {
      MSFT_TaskDailyTrigger: 86400,
      MSFT_TaskWeeklyTrigger: 604800,
      MSFT_TaskMonthlyTrigger: 2592000,
      MSFT_TaskMonthlyDOWTrigger: 2592000,
    }[t.kind] || null
    return seconds && (!best || seconds < best) ? seconds : best
  }, null)
  // LastTaskResult 267011 = task never ran; 267008 = no next run scheduled.
  const neverRan = lastRunTime === null || lastTaskResult === 267011
  const exitCode = (lastTaskResult === null || lastTaskResult === 267011 || lastTaskResult === 267008)
    ? null : lastTaskResult
  const enabled = state !== 1
  // MSFT_ScheduledTask State: 0 Unknown, 1 Disabled, 2 Queued, 3 Ready, 4 Running.
  let runtimeStatus = 'unloaded'
  if (state === 2 || state === 3 || state === 4) runtimeStatus = 'loaded'
  else if (!enabled) runtimeStatus = 'disabled'
  const running = state === 4
  return {
    id: `task:${id}`,
    kind: 'launch',
    management: runtimeStatus === 'loaded' ? 'scheduled' : 'definition',
    runtimeStatus,
    category: 'other',
    sourceStatus: 'loaded',
    groupLabel: null,
    title: record.Name || id,
    program: record.ActionExecute || null,
    args: record.ActionArguments ? record.ActionArguments.trim().split(/\s+/).filter(Boolean) : [],
    workingDirectory: record.ActionWorkingDirectory || null,
    scope: systemTask ? 'system' : 'user',
    plistPath: id,
    stdoutPath: null,
    stderrPath: null,
    interval: repetitionSeconds || scheduleSeconds,
    enabled,
    keepAlive,
    runAtLoad,
    running,
    pid: null,
    exitCode,
    neverRan,
    lastUpdate: lastRunTime ? Date.parse(lastRunTime) : running ? now : null,
    lastRunTime,
    nextRunTime: record.NextRunTime || null,
    missedRuns,
    createdAt: null,
    updatedAt: null,
  }
}

/** Win32_Service row -> launch-task shape. */
export function parseWindowsService(record) {
  const id = `service:${record.Name}`
  const startMode = String(record.StartMode || '')
  const state = String(record.State || '')
  const auto = startMode === 'Auto'
  const disabled = startMode === 'Disabled'
  const running = state === 'Running'
  // Win32_Service.ExitCode is 1077 (ERROR_SERVICE_NEVER_STARTED) for a
  // service that simply never started — that is not a failure, so it maps
  // to a null exit code. Only a real exit code counts as a failure signal.
  const rawExit = Number(record.ExitCode)
  const exitCode = running || state === 'Stopped'
    ? (rawExit === 1077 ? null : rawExit || 0)
    : null
  return {
    id,
    kind: 'launch',
    management: running ? 'service' : 'definition',
    runtimeStatus: running ? 'loaded' : disabled ? 'disabled' : 'unloaded',
    category: 'other',
    sourceStatus: 'loaded',
    groupLabel: null,
    title: record.DisplayName || record.Name,
    program: record.PathName ? record.PathName.trim().split(/\s+/)[0].replace(/^"/, '').replace(/"$/, '') : null,
    args: record.PathName ? record.PathName.trim().split(/\s+/).slice(1) : [],
    workingDirectory: null,
    scope: 'system',
    plistPath: id,
    stdoutPath: null,
    stderrPath: null,
    interval: null,
    enabled: !disabled,
    keepAlive: auto,
    runAtLoad: auto,
    running,
    pid: Number(record.ProcessId) || null,
    exitCode,
    neverRan: false,
    lastUpdate: null,
    lastRunTime: null,
    nextRunTime: null,
    missedRuns: 0,
    createdAt: null,
    updatedAt: null,
  }
}

/**
 * The traffic light itself (unchanged from the macOS original).
 *
 * ok    running, and (when the job reports on a schedule) its log is current
 * warn  running but silent for longer than its schedule implies, or idle-long
 * fail  stopped with a non-zero last exit, or declared KeepAlive without a process
 * idle  scheduled, never ran yet (or last run was clean and is simply waiting)
 */
export function classify(task, now) {
  if (task.runtimeStatus === 'not-loaded') return {state:'idle',reason:'not-loaded'}
  if (task.runtimeStatus === 'unknown') return {state:'idle',reason:'runtime-unknown'}
  const intervalMs = task.interval ? task.interval * 1000 : null
  const staleAfter = intervalMs ? Math.max(intervalMs * 2.5, 15 * 60 * 1000) : 30 * 60 * 60 * 1000
  const logAge = typeof task.lastUpdate === 'number' ? now - task.lastUpdate : null
  const stale = logAge !== null && logAge > staleAfter

  if (task.running) {
    if (stale && !task.keepAlive) {
      return { state: 'warn', reason: 'running-but-quiet' }
    }
    return { state: 'ok', reason: 'running' }
  }
  if (typeof task.exitCode === 'number' && task.exitCode !== 0) {
    return { state: 'fail', reason: 'exited-nonzero' }
  }
  if (task.keepAlive) {
    return { state: 'fail', reason: 'keepalive-down' }
  }
  if (task.neverRan) {
    return { state: 'idle', reason: 'not-run-yet' }
  }
  return { state: stale ? 'warn' : 'ok', reason: stale ? 'stale-output' : 'waiting' }
}

export async function collectLaunchTasks(now = Date.now()) {
  const gaps = []
  let data
  try {
    data = await runPowerShell(TASKS_SCRIPT, 30000)
  } catch (error) {
    return { tasks: [], observedAt: new Date().toISOString(), gaps: [`Scheduled-task query failed: ${error.message}`] }
  }
  const tasks = (Array.isArray(data.tasks) ? data.tasks : []).map(r => {
    const task = parseWindowsTask(r, now)
    return { ...task, ...classify(task, now) }
  })
  const services = (Array.isArray(data.services) ? data.services : []).map(r => {
    const task = parseWindowsService(r)
    return { ...task, ...classify(task, now) }
  })
  return { tasks: [...tasks, ...services], observedAt: new Date().toISOString(), gaps }
}

function shortenPath(value) {
  const home = homedir()
  return typeof value === 'string' && value.startsWith(home) ? `~${value.slice(home.length)}` : value
}

/**
 * Reads the hand-edited notes file. Creates a template on first run so the
 * "what is this job?" column is one edit away instead of a blank wall.
 */
async function readNotes(tasks) {
  const display = shortenPath(NOTES_PATH)
  let raw = null
  try {
    raw = await readFile(NOTES_PATH, 'utf8')
  } catch (error) {
    if (!error || error.code !== 'ENOENT') {
      return { notes: {}, meta: { path: display, error: 'unreadable' } }
    }
  }

  if (raw === null) {
    const template = {
      _help: '一句话说明每个任务在干什么。键是任务 ID（如 task:\\Microsoft\\Windows\\... 或 service:...），值是说明；保存后 15 秒内生效。',
      notes: Object.fromEntries(tasks.map(task => [task.id, ''])),
    }
    try {
      await mkdir(dirname(NOTES_PATH), { recursive: true })
      await writeFile(NOTES_PATH, `${JSON.stringify(template, null, 2)}\n`, 'utf8')
      return { notes: {}, meta: { path: display, created: true, filled: 0, total: tasks.length } }
    } catch {
      return { notes: {}, meta: { path: display, error: 'unwritable' } }
    }
  }

  try {
    const parsed = JSON.parse(raw)
    const notes = parsed && typeof parsed.notes === 'object' && parsed.notes ? parsed.notes : {}
    const filled = tasks.filter(task => {
      const value = notes[task.id]
      return typeof value === 'string' && value.trim().length > 0
    }).length
    return { notes, meta: { path: display, filled, total: tasks.length } }
  } catch {
    return { notes: {}, meta: { path: display, error: 'invalid-json' } }
  }
}

/**
 * Our own inferred lines: shipped defaults, optionally overridden by
 * `~/.config/dsh-ops-board/auto.json` (same shape as notes.json).
 */
async function readAuto() {
  const merged = { ...AUTO_DEFAULTS }
  try {
    const raw = await readFile(AUTO_PATH, 'utf8')
    const parsed = JSON.parse(raw)
    const notes = parsed && typeof parsed.notes === 'object' && parsed.notes ? parsed.notes : parsed
    for (const [key, value] of Object.entries(notes || {})) {
      if (typeof value === 'string') merged[key] = value.trim()
    }
  } catch {
    // Missing or malformed overrides keep the shipped defaults.
  }
  return merged
}

async function collect() {
  const now = Date.now()
  const { tasks, observedAt: launchedAt, gaps } = await collectLaunchTasks(now)
  const auto = await readAuto()
  const processes = await collectProcesses(tasks)
  const { notes, meta: notesMeta } = await readNotes(tasks)
  for (const task of tasks) {
    const value = notes[task.id]
    task.note = typeof value === 'string' && value.trim() ? value.trim() : null
    task.autoNote = typeof auto[task.id] === 'string' && auto[task.id].trim() ? auto[task.id] : null
  }

  tasks.push(...processes.tasks)
  const rank = { fail: 0, warn: 1, idle: 2, ok: 3 }
  tasks.sort((left, right) => {
    const delta = (rank[left.state] ?? 9) - (rank[right.state] ?? 9)
    return delta !== 0 ? delta : left.title.localeCompare(right.title)
  })

  const summary = { total: tasks.length, ok: 0, warn: 0, fail: 0, idle: 0 }
  for (const task of tasks) summary[task.state] = (summary[task.state] || 0) + 1

  return {
    generatedAt: new Date(now).toISOString(),
    host: hostname(),
    sources: ['Task Scheduler (all tasks)', 'Windows services', 'current-user processes (Win32_Process + Get-NetTCPConnection)'],
    processes: {observedAt: processes.observedAt, gaps: processes.gaps, metrics: processes.metrics},
    summary,
    notes: notesMeta,
    tasks,
  }
}

let cache = { at: 0, value: null }

async function snapshot() {
  if (cache.value && Date.now() - cache.at < CACHE_MS) return cache.value
  const value = await collect()
  cache = { at: Date.now(), value }
  return value
}

export { collect }

export function apply(ctx) {
  ctx.effect(() =>
    ctx.webServer.register({
      kind: 'exact',
      path: STATE_PATH,
      handler: async (_req, res) => {
        try {
          const body = JSON.stringify(await snapshot())
          res.writeHead(200, {
            'content-type': 'application/json; charset=utf-8',
            'cache-control': 'no-store',
          })
          res.end(body)
        } catch (error) {
          res.writeHead(500, { 'content-type': 'application/json; charset=utf-8' })
          res.end(JSON.stringify({ error: String(error && error.message ? error.message : error) }))
        }
      },
    }),
  )
}
