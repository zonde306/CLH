'use strict';
const fs = require('node:fs'), path = require('node:path'), { spawn } = require('node:child_process');
// Native decoders (texture2ddecoder/astc-encoder/etcpak) crash the interpreter
// while importing in free-threaded builds, so the worker can die without a
// Python traceback. Translate the OS status instead of hiding it.
function failure(status, error) {
  if (typeof status === 'number' && (status >>> 0) >= 0x80000000)
    return new Error((error || '') + 'Python 进程异常退出（' + (status >>> 0).toString(16) + '）。请用标准版（非自由线程）CPython 重新安装依赖：install-python.cmd。');
  return new Error(error || 'Unity 素材解包失败。');
}
function runUnity(request, { worker = path.join(__dirname, '../python/export_unity.py'), pythonEnv = 'MUVLUV_PYTHON' }: any = {}) {
  const executable = process.env[pythonEnv] || process.env.VAULT_PYTHON || path.resolve(__dirname, '../../../.tools/python/muvluv-ggx', process.platform === 'win32' ? 'Scripts/python.exe' : 'bin/python');
  if (!fs.existsSync(executable)) throw new Error('请运行 install-python.cmd，为 Muv-Luv 安装 Python 依赖。');
  return new Promise((resolve, reject) => {
    const child = spawn(executable, ['-X', 'utf8', worker], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    let output = '', error = ''; let rejected = false;
    child.stdout.on('data', part => { output += part; if (output.length > 16 * 1024 * 1024 && !rejected) { rejected = true; child.kill(); reject(new Error('解包输出超过大小限制。')); } });
    child.stderr.on('data', part => { error = (error + part).slice(-2500); });
    child.on('error', reject); child.on('exit', code => { if (rejected) return; if (code) reject(failure(code, error)); else try { resolve(JSON.parse(output)); } catch { reject(new Error('Unity 解包结果无效。')); } });
    child.stdin.end(JSON.stringify(request));
  });
}
export { runUnity };
