'use strict';
const http = require('node:http');
const https = require('node:https');
const dns = require('node:dns/promises');
const net = require('node:net');
const { Readable } = require('node:stream');
const zlib = require('node:zlib');
const { selectProxy, createProxyConnection } = require('./proxy-env.ts');

// 代理模式下连接由 createConnection 接管，本地不得再解析上游域名；
// 这里给 lookup 一个会报错的替身，避免将来静默退回直连。
function noUpstreamLookup() { throw new Error('代理模式下仍尝试解析上游地址。'); }

// Exact built-in resource/API hosts only. Never derive this allowlist from
// imported catalogs, request headers or caller options, or match whole suffixes.
const fakeIpHosts = new Set([
  'api.abyss-prod-r18.dotabyss.dmmgames.com',
  'drc1bk94f7rq8.cloudfront.net',
  'dugrqaqinbtcq.cloudfront.net',
  'web-assets.otogi-frontier.com',
  'otogi-rest.otogi-frontier.com',
  'assets.muvluv-girls-garden.com',
  'api-game.muvluv-girls-garden.com',
  'cdn-r18.gc.dmmgames.com',
  'www-r18.gc.dmmgames.com',
  'd3mya90gbacu0m.cloudfront.net'
]);

// Exact session bootstrap/renewal endpoints only. This never permits gameplay
// or account linking.
const sessionUrls = new Set(['getHelloToken', 'registerGuestAccount', 'getAccessToken']
  .map(action => `https://api-game.muvluv-girls-garden.com/api/Account/${action}`));

// Conservatively exclude special-purpose IPv6, including 6to4/Teredo which can
// embed a private IPv4 destination. BlockList also handles expanded spellings.
const restrictedV6 = new net.BlockList();
for (const [network, prefix] of [['2001::', 23], ['2001:db8::', 32], ['2002::', 16], ['3fff::', 20]]) {
  restrictedV6.addSubnet(network, prefix, 'ipv6');
}
const benchmarkV6 = new net.BlockList();
benchmarkV6.addSubnet('2001:2::', 48, 'ipv6');

function isPublicAddress(address) {
  if (net.isIP(address) === 4) {
    const [a, b, c] = address.split('.').map(Number);
    return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b <= 127)
      || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
      || (a === 192 && (b === 168 || b === 0 || (b === 88 && c === 99)))
      || (a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
      || (a === 203 && b === 0 && c === 113));
  }
  return net.isIP(address) === 6 && /^[23]/i.test(address) && !restrictedV6.check(address, 'ipv6');
}

function isFakeIpAddress(address) {
  if (net.isIP(address) !== 4) return false;
  const [a, b] = address.split('.').map(Number);
  return a === 198 && (b === 18 || b === 19);
}

async function requestResource(input, { signal, headers = {}, method = 'GET', body }: any = {}, installedModule = false) {
  let url;
  try { url = new URL(input); }
  catch { throw new Error('资源地址格式有误。'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) throw new Error('只支持无账号凭据的 HTTP(S) 资源地址。');
  const moduleHttps = installedModule && url.protocol === 'https:' && !url.port;
  if (method !== 'GET' && !(method === 'POST' && (sessionUrls.has(url.href) || moduleHttps))) throw new Error('该资源地址不支持此请求方式。');
  if (body != null && (method !== 'POST' || typeof body !== 'string' || Buffer.byteLength(body) > 16384)) throw new Error('资源请求正文无效或超过大小限制。');
  const hostname = url.hostname.replace(/^\[|\]$/g, '');
  const literal = net.isIP(hostname);
  // 环境变量配置代理时由代理负责域名解析，本地不再查 DNS；localhost 等直连流量仍按原策略校验。
  const proxy = selectProxy(url);
  let resolved = [];
  if (literal) resolved = [{ address: hostname, family: literal }];
  else if (!proxy) resolved = await dns.lookup(hostname, { all: true });
  // Some proxy DNS configurations pair a usable A record with a benchmarking
  // AAAA record. Drop that reserved IPv6 candidate instead of rejecting the A
  // record too; it must never reach the connection's pinned lookup results.
  const addresses = resolved.filter(item => !(net.isIP(item.address) === 6 && benchmarkV6.check(item.address, 'ipv6')));
  // Only built-in hosts or trusted installed adapters may use proxy Fake-IP DNS
  // over HTTPS/443. Authenticate that same hostname with TLS below; literal IPs
  // and all other private/reserved destinations stay blocked.
  const allowFakeIp = !literal && url.protocol === 'https:' && !url.port && (fakeIpHosts.has(hostname) || moduleHttps);
  if (!proxy && (!addresses.length || addresses.some(item => !isPublicAddress(item.address)
    && !(allowFakeIp && isFakeIpAddress(item.address))))) throw new Error('资源 URL 需要指向公网地址。');
  const requestHeaders = new Headers(headers);
  requestHeaders.set('host', url.host);
  requestHeaders.set('accept-encoding', 'identity');
  requestHeaders.delete('transfer-encoding');
  if (method === 'POST') requestHeaders.set('content-length', String(body == null ? 0 : Buffer.byteLength(body)));
  else requestHeaders.delete('content-length');
  // 代理模式下 socket 由 proxy-env.ts 建立（HTTP CONNECT 或 SOCKS5），
  // 目标地址与端口同样来自已校验的 URL；直连时沿用原来的地址固定逻辑。
  // createConnection 必须挂在 Agent 实例上，写进 request 选项会被忽略；
  // https 目标要用 https.Agent，TLS 仍由该 createConnection 完成，不会被重复包装。
  const proxyAgent: any = proxy ? new (url.protocol === 'https:' ? https.Agent : http.Agent)({ keepAlive: false }) : false;
  if (proxy) proxyAgent.createConnection = createProxyConnection({ proxy, target: { protocol: url.protocol, host: hostname, port: Number(url.port) || (url.protocol === 'https:' ? 443 : 80), servername: literal ? undefined : hostname }, signal });
  const pinnedLookup = (_host, options, callback) => options.all
    ? callback(null, addresses) : callback(null, addresses[0].address, addresses[0].family);
  const tlsOptions = { rejectUnauthorized: true };
  if (url.protocol === 'https:' && !literal) tlsOptions['servername'] = hostname;
  return new Promise<Response>((resolve, reject) => {
    const request = (url.protocol === 'https:' ? https : http).request(url, {
      method, signal, headers: Object.fromEntries(requestHeaders), agent: proxyAgent,
      ...(url.protocol === 'https:' ? tlsOptions : {}),
      // Pin the validated addresses for this connection; do not resolve the host again.
      lookup: proxy ? noUpstreamLookup : pinnedLookup
    }, response => {
      try {
        const headers = new Headers(Object.entries<any>(response.headers).filter(([, value]) => value != null)
          .map(([name, value]) => [name, Array.isArray(value) ? value.join(', ') : value]));
        if ([204, 205, 304].includes(response.statusCode)) { response.resume(); resolve(new Response(null, { status: response.statusCode, headers })); return; }
        let stream = response;
        const compression = { gzip: zlib.createGunzip, br: zlib.createBrotliDecompress, deflate: zlib.createInflate }[headers.get('content-encoding')];
        if (compression) {
          stream = compression(); response.on('error', error => stream.destroy(error)); response.pipe(stream);
          stream.on('close', () => response.destroy());
          headers.delete('content-length'); headers.delete('content-encoding');
        }
        resolve(new Response(Readable.toWeb(stream), { status: response.statusCode, headers }));
      } catch (error) { response.destroy(); reject(error); }
    });
    request.on('error', reject); request.end(body);
  });
}
function fetchPublicResource(input, options: any = {}) { return requestResource(input, options); }
// Installed adapters already execute trusted local Node code and own their API
// and CDN addresses. Give only adapter services this HTTPS transport; arbitrary
// URL downloads keep the public policy, and neither caller can disable TLS.
function fetchModuleResource(input, options: any = {}) { return requestResource(input, options, true); }
export { fetchPublicResource, fetchModuleResource, isPublicAddress };
