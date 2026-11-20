import {execFile} from 'node:child_process'
import {promisify} from 'node:util'
import {createHash} from 'node:crypto'
import {stat} from 'node:fs/promises'
import {basename, dirname, join, parse} from 'node:path'
import {homedir} from 'node:os'

const exec = promisify(execFile)
const hash = value => createHash('sha256').update(value).digest('hex').slice(0, 24)

/**
 * Developer runtimes, as in the macOS original. Windows command lines carry
 * the runtime as `C:\...\node.exe` (backslash separator, `.exe` suffix), so
 * the match accepts either separator and a `.exe` (or version) suffix.
 */
const runtime = /(?:^|[/\\])(node|nodejs|python[\d.]*|Python|npm|npx|uv|uvicorn|gunicorn|nohup|pm2|tsx|vite|bun|deno)(?=[\s\\/]|$|\.)/i

/** Basename that works for Windows paths on any platform (tests run on Linux). */
function baseName(path) {
  if (!path) return ''
  const parts = String(path).split(/[/\\]/)
  return parts[parts.length - 1]
}

/** First whitespace-delimited token, honouring a leading quoted path. */
function firstToken(command) {
  if (!command) return ''
  const text = command.trim()
  if (text.startsWith('"')) {
    const end = text.indexOf('"', 1)
    return end === -1 ? text.slice(1) : text.slice(1, end)
  }
  return text.split(/\s+/)[0]
}

/** Windows absolute path: drive letter, UNC share, or POSIX root. */
function isAbsolutePath(value) {
  return typeof value === 'string' && /^(?:[A-Za-z]:[\\/]|\\\\|\/)/.test(value)
}

/**
 * Run a PowerShell script on Windows and parse its JSON output.
 *
 * The script is passed via -EncodedCommand (UTF-16LE base64): feeding a
 * multi-line script through stdin (`powershell -Command -`) silently drops
 * statements on this host, so stdin is never used for the script itself.
 * The script is expected to set $ProgressPreference='SilentlyContinue' and
 * [Console]::OutputEncoding to UTF-8 first, and to print exactly one JSON
 * document. Anything before the first `{` or `[` (progress/error CLIXML) is
 * discarded before parsing. A missing powershell.exe (non-Windows) rejects,
 * and callers degrade gracefully.
 */
export async function runPowerShell(script, timeout = 30000) {
  const encoded = Buffer.from(script, 'utf16le').toString('base64')
  const { stdout } = await exec('powershell.exe',
    ['-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
    { timeout, maxBuffer: 64 * 1024 * 1024, windowsHide: true })
  // The JSON document is a single line. Error records surface as CLIXML on
  // stdout, so take the first line that starts a JSON document rather than
  // the first '{' anywhere (an error message may contain one).
  const lines = String(stdout).split(/\r?\n/)
  const jsonLine = lines.find(line => {
    const trimmed = line.trim()
    return trimmed.startsWith('{') || trimmed.startsWith('[')
  })
  if (jsonLine === undefined) throw new Error('PowerShell returned no JSON output')
  return JSON.parse(jsonLine)
}

/** Single PowerShell collection: processes + TCP listeners + CPU count. */
export const COLLECT_SCRIPT = `
$ProgressPreference='SilentlyContinue'
[Console]::OutputEncoding=[System.Text.Encoding]::UTF8
function IsoOrNull($d) { if ($d -and $d.Year -gt 2000) { $d.ToString('o') } else { $null } }
$procs = Get-CimInstance Win32_Process | ForEach-Object {
  $cpu = ([double]$_.KernelModeTime + [double]$_.UserModeTime) / 1e7
  [pscustomobject]@{Id=$_.ProcessId;ParentId=$_.ParentProcessId;Name=$_.Name;ExecutablePath=$_.ExecutablePath;CommandLine=$_.CommandLine;WorkingSetMB=[math]::Round($_.WorkingSetSize/1MB,3);CpuSeconds=[math]::Round($cpu,3);StartTime=IsoOrNull $_.CreationDate}
}
$tcp = Get-NetTCPConnection -State Listen | ForEach-Object {
  [pscustomobject]@{LocalAddress=$_.LocalAddress;LocalPort=$_.LocalPort;OwningProcess=$_.OwningProcess}
}
[pscustomobject]@{logicalProcessors=[int]$env:NUMBER_OF_PROCESSORS;processes=$procs;tcp=$tcp} | ConvertTo-Json -Depth 3 -Compress
`

/**
 * Win32_Process rows -> the internal process shape the grouping logic expects.
 * cpuPercent is the lifetime average (total CPU seconds / elapsed seconds /
 * logical processors), the same meaning as `ps` %CPU on macOS.
 * The raw command line is kept in memory only: it can contain secrets
 * (tokens, API keys), so it is hashed into `identity` and never published.
 */
export function parseWindowsProcesses(records, logicalProcessors, nowMs = Date.now()) {
  const cpus = Number(logicalProcessors) > 0 ? Number(logicalProcessors) : 1
  return (records || []).flatMap(record => {
    const pid = Number(record.Id)
    if (!Number.isFinite(pid)) return []
    const command = record.CommandLine || record.ExecutablePath || record.Name || ''
    const startedAtMs = record.StartTime ? Date.parse(record.StartTime) : NaN
    const elapsedSec = Number.isFinite(startedAtMs) ? Math.max((nowMs - startedAtMs) / 1000, 1) : null
    const cpuPercent = elapsedSec && Number(record.CpuSeconds) > 0
      ? Number(((Number(record.CpuSeconds) / elapsedSec / cpus) * 100).toFixed(1))
      : 0
    // Prefer the runtime in the executable's own name: the install directory
    // itself can match first (C:\Program Files\nodejs\node.exe -> 'node',
    // not the 'nodejs' directory). Fall back to the whole command line.
    const exeBase = baseName(firstToken(command)).replace(/\.exe$/i, '')
    const program = runtime.exec(exeBase)?.[1]
      || runtime.exec(command)?.[1]
      || baseName(firstToken(command))
      || record.Name || 'process'
    return [{
      pid,
      ppid: Number(record.ParentId) || 0,
      cpuPercent,
      rssMiB: Number(record.WorkingSetMB) || 0,
      startedAt: record.StartTime || null,
      command,
      identity: hash(`${pid}:${record.StartTime || ''}:${command}`),
      program,
      executablePath: record.ExecutablePath || null,
    }]
  })
}

/** Get-NetTCPConnection rows -> pid -> { ports, cwd }. No cwd on Windows. */
export function parseWindowsTcp(records) {
  const result = new Map()
  for (const record of records || []) {
    const pid = Number(record.OwningProcess)
    if (!Number.isFinite(pid)) continue
    const address = String(record.LocalAddress || '')
    const port = Number(record.LocalPort)
    if (!Number.isFinite(port)) continue
    const host = address === '0.0.0.0' || address === '::' ? '*'
      : address.includes(':') ? `[${address}]`
      : address
    const entry = result.get(pid) || { ports: [], cwd: null }
    const name = `${host}:${port}`
    if (!entry.ports.includes(name)) entry.ports.push(name)
    result.set(pid, entry)
  }
  return result
}

export function agentTool(command, cwd='') {
  const text = `${command} ${cwd}`
  for (const [pattern,name] of [
    [/blender-mcp/i,'Blender MCP'], [/cua-repl/i,'Computer Use'], [/code-review-plugin/i,'Code Review MCP'],
    [/codex-app-tools/i,'Codex App Tools'], [/ops-board.*(?:server|index)|ops-board-codex/i,'Always-on Board MCP'],
    [/node_repl|kernel\.js|trusted-worker\.js/i,'Agent JavaScript Runtime'], [/artifact-session/i,'Artifact Runtime'],
  ]) if (pattern.test(text)) return name
  const plugin = text.match(/[/\\]plugins[/\\]cache[/\\]([^/\\\s]+)[/\\]([^/\\\s]+)/)
  return plugin ? `Plugin: ${plugin[2]}` : null
}

export async function projectPath(cwd, cache) {
  // Only absolute paths: a relative working directory (a scheduled task can
  // carry one) would make dirname() stall at '.' forever.
  if (!cwd || !isAbsolutePath(cwd) || cwd === homedir() || cwd === parse(cwd).root) return null
  if (cache.has(cwd)) return cache.get(cwd)
  let dir=cwd, found=null, depth=0
  while (dir !== parse(dir).root && dir !== homedir() && depth++ < 64) {
    if (await stat(join(dir,'.git')).then(()=>true,()=>false)) { found=dir; break }
    if (!found && (await Promise.all(['package.json','pyproject.toml','Cargo.toml','go.mod'].map(f=>stat(join(dir,f)).then(()=>true,()=>false)))).some(Boolean)) found=dir
    dir=dirname(dir)
  }
  // Unmarked working directories are useful, but never claim verified project ownership.
  cache.set(cwd,found || cwd)
  return found || cwd
}

export function buildProcessGroups(processes, metadata, launchTasks, projectPaths = new Map()) {
  const byPid=new Map(processes.map(p=>[p.pid,p])), children=new Map()
  for (const p of processes) { if (!children.has(p.ppid)) children.set(p.ppid,[]); children.get(p.ppid).push(p.pid) }
  const selected=new Set(), assigned=new Set(), groups=new Map()
  const tree = root => { const ids=[], seen=new Set(); const visit=pid=>{ if(seen.has(pid)||!byPid.has(pid))return;seen.add(pid);ids.push(pid);for(const c of children.get(pid)||[])visit(c) };visit(root);return ids }
  const resource = ids => {
    const members=ids.map(pid=>{const p=byPid.get(pid), m=metadata.get(pid);return {pid,ppid:p.ppid,startedAt:p.startedAt,identity:p.identity,program:p.program,cpuPercent:p.cpuPercent,rssMiB:p.rssMiB,cwd:m?.cwd || null,ports:m ? m.ports : null}})
    return {members,cpuPercent:Number(members.reduce((n,p)=>n+p.cpuPercent,0).toFixed(1)),rssMiB:Number(members.reduce((n,p)=>n+p.rssMiB,0).toFixed(1)),
      ports:members.every(p=>p.ports!==null)?[...new Set(members.flatMap(p=>p.ports))].sort():null}
  }
  for(const task of launchTasks) {
    if (!task.pid || !byPid.has(task.pid)) continue
    const ids=tree(task.pid);ids.forEach(pid=>assigned.add(pid));Object.assign(task,resource(ids));task.rootPids=[task.pid];task.observedAt=processes.observedAt
  }
  for(const p of processes) if(runtime.test(p.command)) for(const pid of tree(p.pid)) selected.add(pid)
  for(const pid of assigned) selected.delete(pid)
  for(const pid of selected) {
    const p=byPid.get(pid)
    if(selected.has(p.ppid))continue
    const ids=tree(pid).filter(id=>selected.has(id)), m=metadata.get(pid)
    const tool=agentTool(p.command,m?.cwd || ''), project=projectPaths.get(p.pid) || projectPaths.get(m?.cwd) || m?.cwd || null
    const category=tool?'agent':project && project!=='/' && project!==homedir()?'project':'other'
    const label=tool || (category==='project'?basename(project):'Unattributed processes')
    const key=`${category}:${tool || (category==='project'?project:`${p.program}:${pid}`)}`
    if(!groups.has(key))groups.set(key,{id:`process:${hash(key)}`,kind:'process',category,management:'unassociated',sourceStatus:'unknown',groupLabel:label,title:label,projectPath:category==='project'?project:null,
      scope:'user',program:p.program,args:[],running:true,state:'ok',reason:'running',pid,rootPids:[],ids:[],lastUpdate:Date.now(),plistPath:null})
    const g=groups.get(key);g.ids.push(...ids);g.rootPids.push(pid)
  }
  return [...groups.values()].map(g=>{const {ids,...rest}=g;return {...rest,...resource([...new Set(ids)]),instanceCount:g.rootPids.length}})
}

export async function collectProcesses(launchTasks) {
  const observedAt=new Date().toISOString(), gaps=[]
  let data
  try {
    data = await runPowerShell(COLLECT_SCRIPT, 30000)
  } catch {
    return {tasks:[],observedAt,gaps:['Process query unavailable; resource values are unknown.']}
  }
  const processes = parseWindowsProcesses(
    Array.isArray(data.processes) ? data.processes : [],
    data.logicalProcessors)
  // Exclude the observer itself. Keep its independently running services visible.
  const filtered = processes.filter(p=>p.pid!==process.pid);filtered.observedAt=observedAt
  const metadata = parseWindowsTcp(Array.isArray(data.tcp) ? data.tcp : [])
  for (const p of filtered) {
    if (!metadata.has(p.pid)) metadata.set(p.pid, {ports: [], cwd: null})
  }
  // Best-effort join: a scheduled task's process is the live process whose
  // executable matches the task's action, preferring a full command-line
  // match (program + arguments). Services are skipped: they share
  // svchost.exe, so an executable match would attach the wrong process.
  const byExecutable = new Map()
  for (const p of filtered) {
    const exe = (p.executablePath || '').toLowerCase()
    if (exe && !byExecutable.has(exe)) byExecutable.set(exe, p.pid)
  }
  for (const task of launchTasks) {
    if (task.pid || task.management !== 'scheduled' || !task.program) continue
    const wanted = `${task.program}${task.args && task.args.length ? ` ${task.args.join(' ')}` : ''}`.toLowerCase()
    const exact = filtered.find(p => p.command && p.command.toLowerCase().startsWith(wanted))
    const pid = exact ? exact.pid : byExecutable.get(task.program.toLowerCase())
    if (pid) task.pid = pid
  }
  const paths=new Map()
  for(const m of metadata.values())if(m.cwd)await projectPath(m.cwd,paths)
  for(const p of filtered) {
    const target=p.command.match(/--directory\s+(.+?)(?=\s+--|$)/)?.[1]
    if(target && isAbsolutePath(target) && await stat(target).then(s=>s.isDirectory(),()=>false)) paths.set(p.pid,await projectPath(target,paths))
  }
  for (const task of launchTasks) {
    const cwd = task.workingDirectory || metadata.get(task.pid)?.cwd
    const command = [task.program,...(task.args || [])].join(' ')
    const tool = agentTool(command,cwd || '')
    const directory = command.match(/--directory\s+(.+?)(?=\s+--|$)/)?.[1]
    const candidate = directory && isAbsolutePath(directory) ? directory : cwd
    const project = candidate ? await projectPath(candidate,paths) : null
    task.category = tool ? 'agent' : project ? 'project' : 'other'
    task.projectPath = tool ? null : project
    task.groupLabel = tool || (project ? basename(project) : null)
    task.purposeEvidence = tool ? 'tool-pattern' : project ? 'directory-inference' : 'unknown'
  }
  const tasks=buildProcessGroups(filtered,metadata,launchTasks,paths).map(t=>({...t,observedAt}))
  if(filtered.some(p=>!metadata.get(p.pid)?.cwd))gaps.push('Some working directories unavailable; project attribution may be incomplete.')
  return {tasks,observedAt,gaps:[...new Set(gaps)],metrics:'CPU: lifetime average (100% = one core); RSS: sum in MiB, shared pages may be counted more than once. Ports: TCP LISTEN only; empty does not prove health. Working directories are not available on Windows, so project attribution uses --directory flags and task working directories.'}
}
