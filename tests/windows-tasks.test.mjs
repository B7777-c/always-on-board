import {test} from 'node:test'
import assert from 'node:assert/strict'
import {parseWindowsTask, parseWindowsService, classify} from '../index.js'

const NOW = Date.parse('2026-11-20T10:30:00.000Z')
const baseTask = (extra = {}) => ({
  Path: '\\Microsoft\\Windows\\UpdateOrchestrator\\',
  Name: 'Reboot',
  State: 3,
  Principal: {UserId: 'NT AUTHORITY\\SYSTEM'},
  ActionExecute: 'C:\\Windows\\System32\\musnotification.exe',
  ActionArguments: '',
  ActionWorkingDirectory: null,
  Triggers: [{
    CimClass: 'MSFT_TaskTimeTrigger', Enabled: true, StartBoundary: '2026-11-20T09:00:00.000Z',
    RepetitionInterval: 'PT1H', RepetitionDuration: null,
    Repetition: {Interval: 'PT1H', Duration: null, StopAtDurationEnd: false, RestartOnFailure: false},
  }],
  Settings: {RestartCount: 0},
  LastRunTime: '2026-11-20T09:00:00.000Z',
  LastTaskResult: 0,
  NextRunTime: '2026-11-20T10:00:00.000Z',
  NumberOfMissedRuns: 0,
  RepetitionSeconds: 3600,
  ...extra,
})

test('ready hourly task maps to a loaded scheduled task with interval and last-update',()=>{
 const task = parseWindowsTask(baseTask(), NOW)
 assert.equal(task.id, 'task:\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot')
 assert.equal(task.kind, 'launch')
 assert.equal(task.management, 'scheduled')
 assert.equal(task.runtimeStatus, 'loaded')
 assert.equal(task.scope, 'system')
 assert.equal(task.interval, 3600)
 assert.equal(task.keepAlive, false)
 assert.equal(task.runAtLoad, false)
 assert.equal(task.neverRan, false)
 assert.equal(task.exitCode, 0)
 assert.equal(task.lastUpdate, Date.parse('2026-11-20T09:00:00.000Z'))
 assert.equal(task.nextRunTime, '2026-11-20T10:00:00.000Z')
 assert.equal(task.plistPath, '\\Microsoft\\Windows\\UpdateOrchestrator\\Reboot')
 assert.deepEqual(classify(task, NOW), {state: 'ok', reason: 'waiting'})
})

test('disabled task reports disabled; logon trigger reports run-at-load',()=>{
 const disabled = parseWindowsTask(baseTask({State: 1}), NOW)
 assert.equal(disabled.runtimeStatus, 'disabled')
 assert.equal(disabled.enabled, false)
 const logon = parseWindowsTask(baseTask({
   Triggers: [{CimClass: 'MSFT_TaskLogonTrigger', Enabled: true, StartBoundary: null, RepetitionInterval: null, RepetitionDuration: null, Repetition: null}],
   RepetitionSeconds: null,
 }), NOW)
 assert.equal(logon.runAtLoad, true)
 assert.equal(logon.interval, null)
})

test('never-ran task (LastTaskResult 267011) has null exit code and classifies idle',()=>{
 const task = parseWindowsTask(baseTask({LastRunTime: null, LastTaskResult: 267011, NextRunTime: null}), NOW)
 assert.equal(task.neverRan, true)
 assert.equal(task.exitCode, null)
 assert.equal(task.lastUpdate, null)
 assert.deepEqual(classify(task, NOW), {state: 'idle', reason: 'not-run-yet'})
})

test('non-zero last exit classifies as failing; stale running task warns',()=>{
 const failed = parseWindowsTask(baseTask({LastTaskResult: 1}), NOW)
 assert.equal(failed.exitCode, 1)
 assert.deepEqual(classify(failed, NOW), {state: 'fail', reason: 'exited-nonzero'})
 const quiet = parseWindowsTask(baseTask({State: 4, LastRunTime: '2026-11-19T09:00:00.000Z'}), NOW)
 assert.equal(quiet.running, true)
 assert.deepEqual(classify(quiet, NOW), {state: 'warn', reason: 'running-but-quiet'})
})

test('restart settings do not imply KeepAlive; daily trigger sets the staleness interval',()=>{
 const restart = parseWindowsTask(baseTask({
   Triggers: [{
     CimClass: 'MSFT_TaskDailyTrigger', Enabled: true, StartBoundary: '2026-11-20T09:00:00.000Z',
     RepetitionInterval: null, RepetitionDuration: null,
     Repetition: {Interval: null, Duration: null, StopAtDurationEnd: false, RestartOnFailure: true},
   }],
   Settings: {RestartCount: 3},
   RepetitionSeconds: null,
 }), NOW)
 assert.equal(restart.keepAlive, false)
 assert.equal(restart.interval, 86400)
 // Last run 1.5h ago, daily cadence: waiting, not stale, not failed.
 assert.deepEqual(classify(restart, NOW), {state: 'ok', reason: 'waiting'})
 // Same task, last run 4 days ago: stale for a daily cadence.
 const overdue = parseWindowsTask(baseTask({
   Triggers: [{
     CimClass: 'MSFT_TaskDailyTrigger', Enabled: true, StartBoundary: '2026-11-16T09:00:00.000Z',
     RepetitionInterval: null, RepetitionDuration: null,
     Repetition: {Interval: null, Duration: null, StopAtDurationEnd: false, RestartOnFailure: true},
   }],
   Settings: {RestartCount: 3},
   RepetitionSeconds: null,
   LastRunTime: '2026-11-16T09:00:00.000Z',
   NextRunTime: '2026-11-21T09:00:00.000Z',
 }), NOW)
 assert.deepEqual(classify(overdue, NOW), {state: 'warn', reason: 'stale-output'})
})

test('user task outside Microsoft path is user-scoped',()=>{
 const task = parseWindowsTask(baseTask({
   Path: '\\', Name: 'MyBackup', Principal: {UserId: 'HOME-PC\\chris'},
 }), NOW)
 assert.equal(task.scope, 'user')
 assert.equal(task.id, 'task:\\MyBackup')
})

test('services map start mode and state; auto service that is stopped classifies as keepalive-down',()=>{
 const running = parseWindowsService({Name: 'Spooler', DisplayName: 'Print Spooler', State: 'Running', StartMode: 'Auto', StartName: 'NT AUTHORITY\\SYSTEM', PathName: 'C:\\Windows\\System32\\spoolsv.exe', ProcessId: 1234, ExitCode: 0})
 assert.equal(running.id, 'service:Spooler')
 assert.equal(running.management, 'service')
 assert.equal(running.runtimeStatus, 'loaded')
 assert.equal(running.keepAlive, true)
 assert.equal(running.runAtLoad, true)
 assert.equal(running.pid, 1234)
 assert.deepEqual(classify(running, NOW), {state: 'ok', reason: 'running'})
 const stopped = parseWindowsService({Name: 'Spooler', DisplayName: 'Print Spooler', State: 'Stopped', StartMode: 'Auto', StartName: 'NT AUTHORITY\\SYSTEM', PathName: 'C:\\Windows\\System32\\spoolsv.exe', ProcessId: 0, ExitCode: 0})
 assert.equal(stopped.management, 'definition')
 assert.deepEqual(classify(stopped, NOW), {state: 'fail', reason: 'keepalive-down'})
 const disabled = parseWindowsService({Name: 'Fax', DisplayName: 'Fax', State: 'Stopped', StartMode: 'Disabled', StartName: 'NT AUTHORITY\\SYSTEM', PathName: 'C:\\Windows\\System32\\fxssvc.exe', ProcessId: 0, ExitCode: 0})
 assert.equal(disabled.runtimeStatus, 'disabled')
 assert.equal(disabled.enabled, false)
})

test('a never-started service (ExitCode 1077) is not a failure; a real failure code is',()=>{
 const neverStarted = parseWindowsService({Name: 'AxInstSV', DisplayName: 'ActiveX Installer', State: 'Stopped', StartMode: 'Manual', StartName: 'NT AUTHORITY\\SYSTEM', PathName: 'C:\\Windows\\System32\\AxInstSV.dll', ProcessId: 0, ExitCode: 1077})
 assert.equal(neverStarted.exitCode, null)
 assert.deepEqual(classify(neverStarted, NOW), {state: 'ok', reason: 'waiting'})
 const failedStart = parseWindowsService({Name: 'BadSvc', DisplayName: 'Bad Service', State: 'Stopped', StartMode: 'Manual', StartName: 'NT AUTHORITY\\SYSTEM', PathName: 'C:\\Windows\\System32\\bad.exe', ProcessId: 0, ExitCode: 1068})
 assert.equal(failedStart.exitCode, 1068)
 assert.deepEqual(classify(failedStart, NOW), {state: 'fail', reason: 'exited-nonzero'})
})
