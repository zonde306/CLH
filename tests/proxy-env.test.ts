'use strict';
/**
 * 出站代理回归测试：
 *   node --import tsx tests/proxy-env.test.ts
 * 覆盖 HTTP CONNECT 隧道、代理认证、SOCKS5、NO_PROXY 直连、
 * 以及直连时不经过代理的对照用例。
 */
import assert from 'node:assert/strict';
import http from 'node:http';
import net from 'node:net';
import test from 'node:test';
const { parseProxy, shouldBypass, selectProxy, snapshotEnvironment } = require('../app/proxy-env.ts');
const { fetchPublicResource } = require('../app/public-fetch.ts');

function listen(server: net.Server | http.Server) {
  return new Promise<number>(resolve => server.listen(0, '127.0.0.1', () => resolve((server.address() as net.AddressInfo).port)));
}

/** 关闭服务器并强制断开残留的隧道/长连接，避免 close() 一直等待 keep-alive socket。 */
function close(server: net.Server | http.Server) {
  const sockets = (server as any)[SOCKETS_KEY] as Set<net.Socket> | undefined;
  if (sockets) for (const socket of sockets) socket.destroy();
  return new Promise<void>(resolve => server.close(() => resolve()));
}

const SOCKETS_KEY = Symbol('sockets');

/** 记录服务器上的所有连接，便于 close 时直接销毁。 */
function trackSockets(server: net.Server | http.Server) {
  const sockets = new Set<net.Socket>();
  (server as any)[SOCKETS_KEY] = sockets;
  server.on('connection', socket => { sockets.add(socket); socket.on('close', () => sockets.delete(socket)); });
  return server;
}

/** 最小 HTTP 代理：明文转发 + CONNECT 隧道，可选 Basic 认证。 */
function createHttpProxy({ auth = null, record = [] }: { auth?: string | null; record?: string[] } = {}) {
  const server = trackSockets(http.createServer((req, res) => {
    const target = new URL(req.url || '');
    record.push(`${req.method} ${target.origin}${target.pathname}`);
    const upstream = http.request({ host: target.hostname, port: target.port || 80, path: target.pathname + target.search, method: req.method, headers: req.headers }, reply => {
      res.writeHead(reply.statusCode || 502, reply.headers); reply.pipe(res);
    });
    upstream.on('error', error => { res.writeHead(502); res.end(error.message); });
    req.pipe(upstream);
  }));
  server.on('connect', (req, clientSocket, head) => {
    if (auth && (req.headers['proxy-authorization'] || '') !== `Basic ${Buffer.from(auth).toString('base64')}`) {
      clientSocket.end('HTTP/1.1 407 Proxy Authentication Required\r\nproxy-authenticate: Basic realm="test"\r\n\r\n'); return;
    }
    const [host, port] = (req.url || '').split(':');
    record.push(`CONNECT ${host}:${port}`);
    const upstream = net.connect({ host, port: Number(port) }, () => {
      clientSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
      if (head?.length) upstream.write(head);
      upstream.pipe(clientSocket); clientSocket.pipe(upstream);
    });
    upstream.on('error', () => clientSocket.destroy());
    clientSocket.on('error', () => upstream.destroy());
  });
  return { server, record };
}

/** 最小 SOCKS5 代理：无认证 CONNECT，供 socks5:// 用例使用。 */
function createSocksProxy({ record = [] }: { record?: string[] } = {}) {
  const server = trackSockets(net.createServer(socket => {
    let stage = 0;
    let buffer = Buffer.alloc(0);
    socket.on('data', chunk => {
      buffer = Buffer.concat([buffer, chunk]);
      for (;;) {
        if (stage === 0) {
          if (buffer.length < 2 || buffer.length < 2 + buffer[1]) break;
          const methods = buffer.subarray(2, 2 + buffer[1]);
          buffer = buffer.subarray(2 + buffer[1]);
          if (!methods.includes(0x00)) { socket.end(Buffer.from([0x05, 0xff])); return; }
          socket.write(Buffer.from([0x05, 0x00])); stage = 1; continue;
        }
        if (stage === 1) {
          if (buffer.length < 4) break;
          const addressType = buffer[3];
          let need = 7 + buffer[4];
          if (addressType === 0x01) need = 10;
          else if (addressType === 0x04) need = 22;
          if (buffer.length < need) break;
          let host: string;
          if (addressType === 0x01) host = Array.from(buffer.subarray(4, 8)).join('.');
          else if (addressType === 0x04) host = Array.from({ length: 8 }, (_, index) => buffer.readUInt16BE(4 + index * 2).toString(16)).join(':');
          else host = buffer.subarray(5, 5 + buffer[4]).toString();
          const port = buffer.readUInt16BE(need - 2);
          buffer = buffer.subarray(need); stage = 2;
          record.push(`SOCKS ${host}:${port}`);
          const upstream = net.connect({ host, port }, () => {
            socket.write(Buffer.from([0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]));
            upstream.pipe(socket); socket.pipe(upstream);
            if (buffer.length) upstream.write(buffer);
          });
          upstream.on('error', () => { socket.end(Buffer.from([0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])); });
          socket.on('error', () => upstream.destroy());
          return;
        }
        break;
      }
    });
    socket.on('error', () => void 0);
  }));
  return { server, record };
}

test('代理地址解析：缺省协议、SOCKS、非法值', () => {
  assert.deepEqual(parseProxy('127.0.0.1:9080')?.kind, 'http');
  assert.equal(parseProxy('127.0.0.1:9080')?.port, 9080);
  assert.equal(parseProxy('https://proxy.local')?.kind, 'http');
  assert.equal(parseProxy('socks5://user:pass@10.0.0.9:1080')?.kind, 'socks5');
  assert.deepEqual(parseProxy('socks5://user:pass@10.0.0.9:1080')?.auth, { user: 'user', pass: 'pass' });
  assert.equal(parseProxy('ftp://proxy.local:21'), null);
  assert.equal(parseProxy('://'), null);
});

test('NO_PROXY：精确主机、子域、CIDR、端口', () => {
  const restore = snapshotEnvironment();
  process.env.NO_PROXY = 'localhost,.example.com,10.0.0.0/8,127.0.0.1:9080';
  try {
    assert.equal(shouldBypass('localhost', 443), true);
    assert.equal(shouldBypass('example.com', 443), true);
    assert.equal(shouldBypass('api.example.com', 443), true);
    assert.equal(shouldBypass('10.1.2.3', 443), true);
    assert.equal(shouldBypass('127.0.0.1', 9080), true);
    assert.equal(shouldBypass('127.0.0.1', 443), false);
    assert.equal(shouldBypass('example.org', 443), false);
  } finally { restore(); }
});

test('代理选择：HTTPS_PROXY 优先于 ALL_PROXY，直连名单生效', () => {
  const restore = snapshotEnvironment();
  try {
    for (const key of ['HTTP_PROXY', 'http_proxy', 'HTTPS_PROXY', 'https_proxy', 'ALL_PROXY', 'all_proxy', 'NO_PROXY', 'no_proxy']) delete process.env[key];
    process.env.ALL_PROXY = 'socks5://127.0.0.1:1080';
    process.env.HTTPS_PROXY = 'http://127.0.0.1:9080';
    assert.equal(selectProxy(new URL('https://example.com/a'))?.port, 9080);
    assert.equal(selectProxy(new URL('http://example.com/a'))?.port, 1080);
    process.env.NO_PROXY = 'example.com';
    assert.equal(selectProxy(new URL('https://example.com/a')), null);
  } finally { restore(); }
});

test('HTTPS 经 HTTP CONNECT 隧道', async () => {
  const restore = snapshotEnvironment();
  const proxy = createHttpProxy();
  const port = await listen(proxy.server);
  try {
    process.env.HTTPS_PROXY = `http://127.0.0.1:${port}`;
    delete process.env.HTTP_PROXY; delete process.env.ALL_PROXY;
    process.env.NO_PROXY = 'localhost,127.0.0.1';
    const response = await fetchPublicResource('https://example.com/');
    assert.equal(response.status, 200);
    assert.match(await response.text(), /Example Domain/);
    assert.deepEqual(proxy.record, ['CONNECT example.com:443']);
  } finally { await close(proxy.server); restore(); }
});

test('HTTP 目标：同样走 CONNECT 隧道（不在代理上暴露明文）', async () => {
  const restore = snapshotEnvironment();
  const proxy = createHttpProxy();
  const port = await listen(proxy.server);
  try {
    process.env.HTTP_PROXY = `http://127.0.0.1:${port}`;
    delete process.env.HTTPS_PROXY; delete process.env.ALL_PROXY;
    process.env.NO_PROXY = 'localhost,127.0.0.1';
    const response = await fetchPublicResource('http://example.com/');
    assert.equal(response.status, 200);
    assert.match(await response.text(), /Example Domain/);
    assert.deepEqual(proxy.record, ['CONNECT example.com:80']);
  } finally { await close(proxy.server); restore(); }
});

test('SOCKS5 代理可用', async () => {
  const restore = snapshotEnvironment();
  const proxy = createSocksProxy();
  const port = await listen(proxy.server);
  try {
    process.env.ALL_PROXY = `socks5://127.0.0.1:${port}`;
    delete process.env.HTTPS_PROXY; delete process.env.HTTP_PROXY;
    process.env.NO_PROXY = 'localhost,127.0.0.1';
    const response = await fetchPublicResource('https://example.com/');
    assert.equal(response.status, 200);
    assert.match(await response.text(), /Example Domain/);
    assert.deepEqual(proxy.record, ['SOCKS example.com:443']);
  } finally { await close(proxy.server); restore(); }
});

test('代理凭据：带认证可用，缺失时明确报错', async () => {
  const restore = snapshotEnvironment();
  const proxy = createHttpProxy({ auth: 'user:secret' });
  const port = await listen(proxy.server);
  try {
    process.env.HTTPS_PROXY = `http://127.0.0.1:${port}`;
    delete process.env.HTTP_PROXY; delete process.env.ALL_PROXY;
    process.env.NO_PROXY = 'localhost,127.0.0.1';
    await assert.rejects(fetchPublicResource('https://example.com/'), /407/);
    process.env.HTTPS_PROXY = `http://user:secret@127.0.0.1:${port}`;
    const response = await fetchPublicResource('https://example.com/');
    assert.equal(response.status, 200);
  } finally { await close(proxy.server); restore(); }
});

test('NO_PROXY 直连：不经过代理，私网地址仍被拒绝', async () => {
  const restore = snapshotEnvironment();
  const proxy = createHttpProxy();
  const port = await listen(proxy.server);
  try {
    process.env.HTTPS_PROXY = `http://127.0.0.1:${port}`;
    delete process.env.HTTP_PROXY; delete process.env.ALL_PROXY;
    process.env.NO_PROXY = 'example.com';
    const response = await fetchPublicResource('https://example.com/');
    assert.equal(response.status, 200);
    assert.deepEqual(proxy.record, []);
  } finally { await close(proxy.server); restore(); }
  // 无代理时私网/保留地址继续被拒绝（拒绝路径不依赖代理是否可用）。
  await assert.rejects(fetchPublicResource('http://127.0.0.1:9/'), /公网地址/);
});
