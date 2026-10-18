'use strict';
const fs=require('node:fs'),path=require('node:path'),{spawnSync}=require('node:child_process');
const readline=require('node:readline/promises');
const {createRegistry}=require('../app/index.ts');
// UnityPy pulls in texture2ddecoder / astc-encoder-py / etcpak. Those wheels
// only publish GIL-enabled ABIs; importing them from a free-threaded CPython
// (python3.14t.exe) crashes the process with an access violation at import.
// Every interpreter we create a venv from must therefore be GIL-enabled.
const PROBE='import sys;print("gil" if sys._is_gil_enabled() else "nogil")';
function probe(command,args){
  const result=spawnSync(command,[...args,'-c',PROBE],{encoding:'utf8',windowsHide:true});
  if(result.error||result.status!==0)return null;
  const text=(result.stdout||'').trim();
  return text==='nogil'?'nogil':text==='gil'?'gil':null;
}
function candidates(){
  if(process.platform!=='win32')return [['python3',[]],['python',[]]];
  // `py -3` picks the newest 3.x, which may be the free-threaded 3.14t build.
  // Name the GIL-enabled installs explicitly before falling back.
  return [['py',['-3.14']],['py',['-3.13']],['py',['-3.12']],['py',['-3.11']],['py',['-3.10']],['python',[]],['py',['-3']]];
}
// Returns the interpreter arguments to build a venv with, preferring a
// GIL-enabled build. A free-threaded interpreter is a last resort only.
function interpreter(){
  let fallback=null;
  for(const [command,args] of candidates()){
    const state=probe(command,args);
    if(state==='gil')return [command,args];
    if(state==='nogil'&&!fallback)fallback=[command,args];
  }
  if(fallback)console.warn('警告：只找到自由线程版 Python，UnityPy 解码模块可能无法加载。建议安装标准版 CPython。');
  return fallback||(process.platform==='win32'?['py',['-3']]:['python3',[]]);
}
function environmentState(environment){
  const python=path.join(environment,process.platform==='win32'?'Scripts/python.exe':'bin/python');
  if(!fs.existsSync(python))return 'missing';
  const result=spawnSync(python,['-c',`import sys;print("nogil" if not sys._is_gil_enabled() else "gil")`],{encoding:'utf8',windowsHide:true});
  if(result.error||result.status!==0)return 'broken';
  return /nogil/.test(result.stdout||'')?'nogil':'gil';
}
async function main(){
  const choices=createRegistry().list().filter(game=>fs.existsSync(path.join(game.root,'requirements.txt')));
  if(!choices.length)throw new Error('此版本没有需要 Python 的游戏。');
  let id=process.argv[2];
  if(!id){choices.forEach((game,index)=>console.log((index+1)+'. '+game.label));const input=readline.createInterface({input:process.stdin,output:process.stdout});const selected=await input.question('输入要安装依赖的游戏序号：');input.close();id=choices[Number(selected)-1]?.id;}
  const game=choices.find(game=>game.id===id);if(!game)throw new Error('请选择列表中的游戏。');
  const root=path.resolve(__dirname,'..'),environment=path.join(root,'.tools/python',id);
  const python=path.join(environment,process.platform==='win32'?'Scripts/python.exe':'bin/python');
  function run(command,args){const result=spawnSync(command,args,{cwd:root,stdio:'inherit',windowsHide:true});if(result.error||result.status!==0)throw new Error(result.error?.message||'安装未完成，请检查 Python 安装与网络连接。');}
  function verify(){const result=spawnSync(python,['-c','import UnityPy.export'],{encoding:'utf8',windowsHide:true});return !result.error&&result.status===0;}
  // A venv built from python3.14t.exe installs cp314t wheels that segfault on
  // import. Rebuild it from a GIL-enabled interpreter so the ABI matches.
  const state=environmentState(environment);
  if(state!=='gil'){
    const [command,args]=interpreter();
    if(fs.existsSync(environment))fs.rmSync(environment,{recursive:true,force:true});
    if(state==='nogil')console.log('检测到自由线程版 Python 环境，正在使用标准版 CPython 重建…');
    run(command,[...args,'-m','venv',environment]);
  }
  run(python,['-m','pip','install','-r',path.join(game.root,'requirements.txt')]);
  if(!verify())throw new Error('Python 依赖无法加载，请确认安装的是标准版（非自由线程）CPython。');
  console.log(game.label+' 的 Python 依赖已安装。');
}
main().catch(error=>{console.error(error.message);process.exitCode=1;});
