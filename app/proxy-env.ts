'use strict';
/**
 * 出站代理支持：完全由标准 *_PROXY 环境变量驱动。
 *
 *   HTTPS_PROXY / https_proxy   访问 https 上游时使用
 *   HTTP_PROXY  / http_proxy    访问 http 上游时使用
 *   ALL_PROXY   / all_proxy     上面两项缺失时的回退
 *   NO_PROXY    / no_proxy      直连名单，逗号或空格分隔
 *
 * 变量名小写优先（与 Node 内置行为一致）。代理地址可省略协议，
 * 支持 http://、https://（按普通 HTTP 代理处理）与 socks5://（可用
 * user:pass@ 提供认证）。不支持的协议、无法解析的地址只告警并忽略，
 * 不会中断下载。
 *
 * 上游连接统一走 CONNECT 隧道（socks5 为 SOCKS5 命令），因此本模块只
 * 负责建立“已经连到上游主机”的 socket，TLS 仍在 app/public-fetch.ts
 * 里按原有策略校验。
 */
const http = require('node:http');
const net = require('node:net');
const tls = require('node:tls');
const { once } = require('node:events');

const SUPPORTED_SCHEMES = new Set(['http:', 'https:', 'socks:', 'socks5:']);
const PROXY_ENV_KEYS = ['HTTPS_PROXY', 'https_proxy', 'HTTP_PROXY', 'http_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy'];
const warned = new Set();

function noop() {}

function env(name) {
  const lower = name.toLowerCase();
  return process.env[lower] || process.env[name.toUpperCase()] || '';
}

function warnOnce(key, message) {
  if (warned.has(key)) return;
  warned.add(key);
  console.warn('[代理] ' + message);
}

function stripBrackets(host) {
  return host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
}

/** 隐藏可能出现在告警里的代理凭据。 */
function redact(text) {
  return String(text).replace(/\/\/[^/@\s]+@/, '//***@');
}

function proxySetting(protocol) {
  const specific = env(protocol === 'https:' ? 'HTTPS_PROXY' : 'HTTP_PROXY');
  return specific || env('ALL_PROXY');
}

function proxySettingName(protocol) {
  if (env(protocol === 'https:' ? 'HTTPS_PROXY' : 'HTTP_PROXY')) return protocol === 'https:' ? 'HTTPS_PROXY' : 'HTTP_PROXY';
  return env('ALL_PROXY') ? 'ALL_PROXY' : '';
}

function parseProxy(raw) {
  const text = String(raw).trim();
  if (!text) return null;
  let url;
  try {
    url = new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(text) ? text : 'http://' + text);
  } catch {
    warnOnce('url:' + text, '忽略无法解析的代理地址：' + redact(text));
    return null;
  }
  if (!SUPPORTED_SCHEMES.has(url.protocol)) {
    warnOnce('scheme:' + url.protocol, '忽略不支持的代理协议 ' + url.protocol + '（请使用 http://、https:// 或 socks5://）。');
    return null;
  }
  const kind = url.protocol.startsWith('socks') ? 'socks5' : 'http';
  const port = Number(url.port || (kind === 'socks5' ? 1080 : 80));
  if (!url.hostname || !Number.isInteger(port) || port < 1 || port > 65535) {
    warnOnce('port:' + text, '忽略地址或端口无效的代理：' + redact(text));
    return null;
  }
  const auth = url.username
    ? { user: decodeURIComponent(url.username), pass: decodeURIComponent(url.password) }
    : null;
  if (auth && (!Buffer.byteLength(auth.user) || Buffer.byteLength(auth.user) > 255 || Buffer.byteLength(auth.pass) > 255)) {
    warnOnce('auth:' + text, '忽略代理凭据过长的代理地址。');
    return null;
  }
  return { kind, host: stripBrackets(url.hostname), port, auth, display: kind + '://' + stripBrackets(url.hostname) + ':' + port };
}

function bypassList() {
  return env('NO_PROXY').split(/[,\s]+/).map(item => item.trim().toLowerCase()).filter(Boolean);
}

function cidrMatches(address, entry) {
  const [network, prefixText] = entry.split('/');
  const family = net.isIP(network);
  const prefix = Number(prefixText);
  if (!family || !Number.isInteger(prefix)) return false;
  const list = new net.BlockList();
  try { list.addSubnet(network, prefix, family === 4 ? 'ipv4' : 'ipv6'); } catch { return false; }
  return list.check(address, family === 4 ? 'ipv4' : 'ipv6');
}

/** 直连判定：* / 精确主机及其子域 / 主机加端口 / CIDR。 */
function shouldBypass(hostname, port) {
  const entries = bypassList();
  if (!entries.length) return false;
  if (entries.includes('*')) return true;
  const host = stripBrackets(hostname).toLowerCase();
  const literal = net.isIP(host);
  for (const entry of entries) {
    if (entry.includes('/')) {
      if (literal && cidrMatches(host, entry)) return true;
      continue;
    }
    const match = /^(\[[^\]]+\]|[^:]+)(?::(\d+))?$/.exec(entry);
    let name = match ? match[1] : entry;
    const entryPort = match && match[2] ? Number(match[2]) : 0;
    if (entryPort && entryPort !== port) continue;
    name = stripBrackets(name);
    // “.example.com”与“*.example.com”都与“example.com”等价，且都覆盖子域。
    if (name.startsWith('*.')) name = name.slice(2);
    else if (name.startsWith('.')) name = name.slice(1);
    if (!name) continue;
    if (host === name || host.endsWith('.' + name)) return true;
  }
  return false;
}

/** 已配置的代理摘要（只用于启动日志，不含凭据）。 */
function proxySummary() {
  const parts = [];
  for (const protocol of ['https:', 'http:']) {
    const name = proxySettingName(protocol);
    if (!name) continue;
    const proxy = parseProxy(proxySetting(protocol));
    if (proxy) parts.push(name + '=' + proxy.display);
  }
  return parts.length ? parts.join(' ') : null;
}

/**
 * 为一次上游请求挑选代理；命中 NO_PROXY 或不支持时返回 null。
 * 私网/保留地址即使在代理模式下也拒绝，避免借代理访问内网。
 */
function selectProxy(url) {
  const raw = proxySetting(url.protocol);
  if (!raw) return null;
  const proxy = parseProxy(raw);
  if (!proxy) return null;
  const host = stripBrackets(url.hostname);
  const literal = net.isIP(host);
  const port = Number(url.port) || (url.protocol === 'https:' ? 443 : 80);
  if (shouldBypass(host, port)) return null;
  if (literal && !isPublicLiteral(host)) throw new Error('资源 URL 需要指向公网地址。');
  return proxy;
}

function isPublicLiteral(address) {
  const family = net.isIP(address);
  const list = new net.BlockList();
  if (family === 4) {
    for (const [network, prefix] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
      ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.88.99.0', 24], ['192.168.0.0', 16],
      ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24], ['224.0.0.0', 4]]) {
      list.addSubnet(network, prefix, 'ipv4');
    }
    return address === '0.0.0.0' ? false : !list.check(address, 'ipv4');
  }
  if (family !== 6) return false;
  for (const [network, prefix] of [['::', 128], ['::1', 128], ['2001::', 23], ['2001:db8::', 32], ['2002::', 16],
    ['3fff::', 20], ['fc00::', 7], ['fe80::', 10], ['ff00::', 8]]) {
    list.addSubnet(network, prefix, 'ipv6');
  }
  return !list.check(address, 'ipv6');
}

function ipv6ToBigInt(address) {
  const text = address.includes('.')
    ? address.replace(/(\d+\.\d+\.\d+\.\d+)$/, (_, quad) => {
      const [a, b, c, d] = quad.split('.').map(Number);
      return ((a << 8 | b).toString(16)) + ':' + ((c << 8 | d).toString(16));
    })
    : address;
  const [head, tail] = text.split('::');
  const headParts = head ? head.split(':') : [];
  const tailParts = tail ? tail.split(':') : [];
  const groups = [...headParts, ...Array(Math.max(0, 8 - headParts.length - tailParts.length)).fill('0'), ...tailParts];
  return groups.reduce((acc, part) => (acc << 16n) | BigInt(parseInt(part || '0', 16)), 0n);
}

function ipv6ToBytes(address) {
  const value = ipv6ToBigInt(address);
  const bytes = Buffer.alloc(16);
  for (let index = 0; index < 16; index++) bytes[15 - index] = Number((value >> BigInt(8 * index)) & 0xffn);
  return bytes;
}

/**
 * 按需读取 socket 上的定长分片。socket 保持 pause 状态，只用 'readable'
 * + read(size) 取字节，剩余数据留在流内部缓冲区，release 后直接 resume，
 * 既不会把已到达的字节丢掉，也不会吞掉后续（HTTPS 时是 TLS 响应）的数据。
 */
function createReader(socket) {
  let waiter = null;
  let failure = null;
  const settle = () => {
    if (!waiter) return;
    if (failure) { const current = waiter; waiter = null; current.reject(failure); return; }
    const chunk = socket.read(waiter.size);
    if (chunk === null) {
      // 数据还没到；若流已结束则直接报错，避免无限等待。
      if (socket.readableEnded) { const current = waiter; waiter = null; current.reject(new Error('代理连接在握手期间关闭。')); }
      return;
    }
    const current = waiter;
    waiter = null;
    current.resolve(chunk);
  };
  const onFailure = error => { failure = failure || error || new Error('代理连接在握手期间关闭。'); settle(); };
  socket.on('readable', settle);
  socket.on('error', onFailure);
  socket.on('close', onFailure);
  socket.pause();
  return {
    read(size) { return new Promise((resolve, reject) => { waiter = { size, resolve, reject }; settle(); }); },
    release() {
      socket.off('readable', settle);
      socket.off('error', onFailure);
      socket.off('close', onFailure);
      socket.resume();
    }
  };
}

async function socksConnect(proxy, target, track) {
  const socket = net.connect({ host: proxy.host, port: proxy.port });
  socket.setNoDelay(true);
  socket.on('error', noop);
  track(socket);
  await once(socket, 'connect');
  const reader = createReader(socket);
  try {
    const methods = proxy.auth ? [0x00, 0x02] : [0x00];
    socket.write(Buffer.from([0x05, methods.length, ...methods]));
    const greeting = await reader.read(2);
    if (greeting[0] !== 0x05) throw new Error('SOCKS 代理握手响应无效。');
    if (greeting[1] === 0x02) {
      if (!proxy.auth) throw new Error('SOCKS 代理要求用户名密码认证，请在代理地址中提供。');
      const user = Buffer.from(proxy.auth.user);
      const pass = Buffer.from(proxy.auth.pass);
      socket.write(Buffer.concat([Buffer.from([0x01, user.length]), user, Buffer.from([pass.length]), pass]));
      const auth = await reader.read(2);
      if (auth[1] !== 0x00) throw new Error('SOCKS 代理拒绝了代理凭据。');
    } else if (greeting[1] !== 0x00) {
      throw new Error('SOCKS 代理选择了不支持的认证方式。');
    }
    const literal = net.isIP(target.host);
    const address = Buffer.from(target.host);
    const request = [0x05, 0x01, 0x00];
    if (literal === 4) request.push(0x01, ...target.host.split('.').map(Number));
    else if (literal === 6) request.push(0x04, ...ipv6ToBytes(target.host));
    else request.push(0x03, address.length, ...address);
    request.push(target.port >> 8, target.port & 0xff);
    socket.write(Buffer.from(request));
    const reply = await reader.read(4);
    if (reply[0] !== 0x05) throw new Error('SOCKS 代理连接响应无效。');
    if (reply[1] !== 0x00) throw new Error('SOCKS 代理无法连接目标地址（错误码 ' + reply[1] + '）。');
    const length = reply[3] === 0x01 ? 4 : reply[3] === 0x04 ? 16 : (await reader.read(1))[0];
    await reader.read(length + 2);
    reader.release();
    return socket;
  } catch (error) {
    reader.release();
    socket.destroy();
    throw error;
  }
}

function httpConnect(proxy, target, track, signal) {
  const host = net.isIP(target.host) === 6 ? '[' + target.host + ']' : target.host;
  const authority = host + ':' + target.port;
  const headers = { host: authority, 'proxy-connection': 'keep-alive' };
  if (proxy.auth) headers['proxy-authorization'] = 'Basic ' + Buffer.from(proxy.auth.user + ':' + proxy.auth.pass).toString('base64');
  return new Promise((resolve, reject) => {
    const request = http.request({ host: proxy.host, port: proxy.port, method: 'CONNECT', path: authority, headers, agent: false, signal }, response => {
      response.resume();
      reject(new Error('HTTP 代理未建立隧道（HTTP ' + response.statusCode + '）。'));
    });
    request.on('connect', (response, socket, head) => {
      request.removeAllListeners('response');
      if (response.statusCode !== 200) { socket.destroy(); reject(new Error('HTTP 代理拒绝隧道（HTTP ' + response.statusCode + '）。')); return; }
      socket.setNoDelay(true);
      socket.on('error', noop);
      if (head && head.length) socket.unshift(head);
      track(socket);
      resolve(socket);
    });
    request.on('error', reject);
    request.end();
  });
}

/**
 * 返回可直接交给 http(s).request 的 createConnection：
 * 先连代理并打通到上游的隧道，https 目标再在隧道上完成 TLS。
 */
function createProxyConnection({ proxy, target, signal }) {
  return (_options, callback) => {
    let current = null;
    let settled = false;
    const abortError = () => (signal && signal.reason instanceof Error ? signal.reason : new Error('请求已取消。'));
    const track = socket => { current = socket; if (signal && signal.aborted) socket.destroy(abortError()); };
    const onAbort = () => { current?.destroy(abortError()); finish(abortError()); };
    if (signal && signal.aborted) { callback(abortError()); return; }
    const cleanup = () => signal?.removeEventListener('abort', onAbort);
    const finish = (error, socket = null) => {
      if (settled) { socket?.destroy(); return; }
      settled = true;
      cleanup();
      if (socket) current = socket;
      callback(error || null, socket);
    };
    signal?.addEventListener('abort', onAbort, { once: true });
    (async () => {
      const raw = proxy.kind === 'socks5'
        ? await socksConnect(proxy, target, track)
        : await httpConnect(proxy, target, track, signal);
      if (target.protocol !== 'https:') { finish(null, raw); return; }
      const secure = tls.connect({ socket: raw, servername: target.servername, rejectUnauthorized: true });
      secure.setNoDelay(true);
      secure.on('error', noop);
      track(secure);
      await once(secure, 'secureConnect');
      finish(null, secure);
    })().catch(error => { current?.destroy(); finish(error); });
  };
}

/** 读取后立即回滚，避免把测试写入环境（仅测试用）。 */
function snapshotEnvironment() {
  const saved = new Map();
  for (const key of PROXY_ENV_KEYS) saved.set(key, process.env[key]);
  return () => {
    for (const [key, value] of saved) { if (value === undefined) delete process.env[key]; else process.env[key] = value; }
  };
}

export { selectProxy, createProxyConnection, proxySummary, shouldBypass, parseProxy, snapshotEnvironment, PROXY_ENV_KEYS };
