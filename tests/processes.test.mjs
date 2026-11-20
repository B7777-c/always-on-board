import {test} from 'node:test'
import assert from 'node:assert/strict'
import {parseWindowsProcesses, parseWindowsTcp, buildProcessGroups} from '../processes.js'

// Shape mirrors the COLLECT_SCRIPT output (Get-CimInstance Win32_Process rows).
const rec=(Id,ParentId,CommandLine,extra={})=>({Id,ParentId,Name:'node.exe',ExecutablePath:'C:\\Program Files\\nodejs\\node.exe',CommandLine,WorkingSetMB:10,CpuSeconds:2,StartTime:'2026-10-21T14:00:00.000Z',...extra})
const p=(pid,ppid,command,extra={})=>({pid,ppid,command,program:'node',startedAt:'2026-10-21T14:00:00.000Z',identity:`identity-${pid}`,cpuPercent:2,rssMiB:10,...extra})
const meta=rows=>new Map(rows.map(([pid,cwd,ports=[]])=>[pid,{cwd,ports}]))

test('Windows process parser preserves command paths with spaces, averages CPU over lifetime, never publishes raw args',()=>{
 const nowMs=Date.parse('2026-10-21T14:01:40.000Z') // 100 s after start
 const rows=parseWindowsProcesses([
   rec(12,1,'"C:\\Program Files\\nodejs\\node.exe" server.js --token=private'),
   rec(13,1,'C:\\Python312\\python.exe app.py',{Name:'python.exe',ExecutablePath:'C:\\Python312\\python.exe'}),
 ],1,nowMs)
 assert.equal(rows.length,2)
 assert.equal(rows[0].program,'node')
 assert.equal(rows[0].cpuPercent,2) // 2 CPU-seconds / 100 s / 1 core
 assert.equal(rows[0].rssMiB,10)
 assert.equal(rows[1].program,'python')
 const groups=buildProcessGroups(rows,meta([[12,null], [13,null]]),[])
 assert.ok(!JSON.stringify(groups).includes('private'))
 assert.ok(!JSON.stringify(groups).includes('command'))
 assert.ok(!JSON.stringify(groups).includes('token'))
 // Identity binds pid + start time + command: a restart changes it.
 const again=parseWindowsProcesses([rec(12,1,'"C:\\Program Files\\nodejs\\node.exe" server.js --token=private',{StartTime:'2026-10-22T14:00:00.000Z'})],1,nowMs)
 assert.notEqual(rows[0].identity,again[0].identity)
})

test('Windows TCP parsing formats wildcard and IPv6 listeners and dedupes ports',()=>{
 const data=parseWindowsTcp([
   {OwningProcess:11,LocalAddress:'127.0.0.1',LocalPort:3000},
   {OwningProcess:11,LocalAddress:'0.0.0.0',LocalPort:8080},
   {OwningProcess:11,LocalAddress:'0.0.0.0',LocalPort:8080},
   {OwningProcess:12,LocalAddress:'::',LocalPort:443},
   {OwningProcess:12,LocalAddress:'::1',LocalPort:9000},
 ])
 assert.deepEqual(data.get(11).ports,['127.0.0.1:3000','*:8080'])
 assert.deepEqual(data.get(12).ports,['*:443','[::1]:9000'])
 assert.equal(data.get(11).cwd,null) // No working directories on Windows.
 const group=buildProcessGroups([p(10,1,'C:\\node.exe app.js')],new Map(),[])[0]
 assert.equal(group.ports,null)
})

test('parents and descendants merge, scheduled-task trees are enriched rather than double counted',()=>{
 const rows=[p(10,1,'C:\\node.exe api.js'),p(11,10,'C:\\node.exe worker.js'),p(12,11,'C:\\helper.exe'),p(20,1,'C:\\node.exe dev.js')]
 const tasks=[{pid:10}];const groups=buildProcessGroups(rows,meta(rows.map(p=>[p.pid,null,['127.0.0.1:3000']])),tasks)
 assert.deepEqual(tasks[0].members.map(p=>p.pid),[10,11,12]);assert.equal(tasks[0].rssMiB,30)
 assert.equal(groups.length,1);assert.deepEqual(groups[0].rootPids,[20]);assert.equal(groups[0].members.length,1)
})

test('independent instances group by project or agent tool, each member counted once',()=>{
 const rows=[p(10,1,'C:\\uv.exe blender-mcp'),p(11,10,'C:\\python.exe blender-mcp'),p(20,1,'C:\\uv.exe blender-mcp'),p(21,20,'C:\\python.exe blender-mcp'),p(30,1,'C:\\node.exe app.js'),p(40,1,'C:\\node.exe app.js')]
 const groups=buildProcessGroups(rows,meta([[10,'C:\\a'],[11,'C:\\a'],[20,'C:\\b'],[21,'C:\\b'],[30,'C:\\project-a'],[40,'C:\\project-b']]),[])
 const tool=groups.find(g=>g.category==='agent');assert.equal(tool.instanceCount,2);assert.equal(tool.members.length,4);assert.equal(tool.cpuPercent,8)
 assert.equal(groups.filter(g=>g.category==='project').length,2)
 assert.equal(new Set(groups.flatMap(g=>g.members.map(p=>p.pid))).size,6)
})

test('cyclic or missing ancestry terminates safely',()=>{
 const groups=buildProcessGroups([p(10,11,'C:\\node.exe a'),p(11,10,'C:\\node.exe b'),p(20,999,'C:\\node.exe c')],new Map(),[])
 assert.equal(groups.length,1);assert.deepEqual(groups[0].rootPids,[20])
})

test('relative working directories never hang project inference', {timeout: 5000}, async()=>{
 const {projectPath}=await import('../processes.js')
 assert.equal(await projectPath('.', new Map()), null)
 assert.equal(await projectPath('relative\\path', new Map()), null)
 assert.equal(await projectPath('', new Map()), null)
})

test('live Windows collection observes a test-owned child listener without exposing arguments', {skip:process.platform!=='win32',timeout:60000}, async()=>{
 const {spawn}=await import('node:child_process')
 const {collectProcesses}=await import('../processes.js')
 const child=spawn(process.execPath,['-e',"require('net').createServer().listen(0,'127.0.0.1',function(){process.send(this.address().port)})",'--','--token=live-test-secret'],{stdio:['ignore','ignore','ignore','ipc']})
 try {
  const port=await new Promise((resolve,reject)=>{child.once('message',resolve);child.once('error',reject);child.once('exit',()=>reject(new Error('Fixture exited before reporting port')))})
  const snapshot=await collectProcesses([])
  const matches=snapshot.tasks.flatMap(t=>t.members).filter(p=>p.pid===child.pid)
  assert.equal(matches.length,1);assert.ok(matches[0].ports.includes(`127.0.0.1:${port}`))
  assert.ok(matches[0].identity);assert.ok(matches[0].startedAt)
  assert.ok(!JSON.stringify(snapshot).includes('live-test-secret'))
 } finally {child.kill();await new Promise(resolve=>child.exitCode!==null||child.signalCode!==null?resolve():child.once('exit',resolve))}
})
