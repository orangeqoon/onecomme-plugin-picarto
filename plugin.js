// @ts-nocheck
'use strict';

const tls = require('tls');
const crypto = require('crypto');
const https = require('https');
const http = require('http');
const fs = require('fs');
const path = require('path');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

let activeSocket = null;
let currentServiceId = null;
let currentChannel = null;
let currentToken = null;
let pingTimer = null;
let reconnectTimer = null;
let seq = 0;
let pluginDir = __dirname;

let connectionStatus = {
  state: 'idle', // 'idle' | 'checking' | 'connected' | 'error'
  lastCheck: null,
  channel: '',
  isLive: false,
  title: '',
  error: null,
};

function log(msg) {
  console.info('[Picartoプラグイン] ' + msg);
}

function loadConfig(dir) {
  const targetDir = dir || pluginDir || __dirname;
  const cfgPath = path.join(targetDir, 'config.json');
  if (fs.existsSync(cfgPath)) {
    try {
      return JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    } catch (_) {}
  }
  return {
    channel: '',
    token: '',
  };
}

function saveConfig(dir, cfg) {
  const targetDir = dir || pluginDir || __dirname;
  const cfgPath = path.join(targetDir, 'config.json');
  try {
    fs.writeFileSync(cfgPath, JSON.stringify(cfg, null, 2), 'utf8');
    return true;
  } catch (err) {
    log('設定保存失敗: ' + err.message);
    return false;
  }
}

// RFC 6455 マスク付き WebSocket フレーム生成
function maskFrame(opcode, payload) {
  const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload, 'utf8');
  const len = buf.length;
  const mask = crypto.randomBytes(4);
  const masked = Buffer.alloc(len);
  for (let i = 0; i < len; i++) masked[i] = buf[i] ^ mask[i % 4];

  let header;
  if (len < 126) {
    header = Buffer.alloc(6);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | len;
    mask.copy(header, 2);
  } else if (len < 65536) {
    header = Buffer.alloc(8);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 126;
    header.writeUInt16BE(len, 2);
    mask.copy(header, 4);
  } else {
    header = Buffer.alloc(14);
    header[0] = 0x80 | opcode;
    header[1] = 0x80 | 127;
    header.writeBigUInt64BE(BigInt(len), 2);
    mask.copy(header, 10);
  }
  return Buffer.concat([header, masked]);
}

// Picarto 公式 REST API でチャンネル情報取得
function fetchChannelInfo(channelName) {
  return new Promise((resolve, reject) => {
    const url = 'https://api.picarto.tv/api/v1/channel/name/' + encodeURIComponent(channelName);
    const req = https.get(
      url,
      {
        headers: {
          'User-Agent': UA,
          'Accept': 'application/json',
        },
        timeout: 8000,
      },
      (res) => {
        if (res.statusCode !== 200) {
          return reject(new Error('Picarto API HTTP ' + res.statusCode));
        }
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            const data = JSON.parse(Buffer.concat(chunks).toString('utf8'));
            resolve({
              userId: data.user_id,
              name: data.name,
              isLive: Boolean(data.online),
              title: data.title || '',
              avatar: data.avatar || '',
              viewers: data.viewers || 0,
            });
          } catch (err) {
            reject(err);
          }
        });
      }
    );
    req.on('error', reject);
    req.on('timeout', () => {
      req.destroy();
      reject(new Error('Picarto API タイムアウト'));
    });
  });
}

// Picarto チャット WebSocket 接続（Pure Node.js TLS）
function connectPicartoChat(channel, token, handlers) {
  const host = 'chat.picarto.tv';
  const port = 443;
  let pathStr;

  if (token && token.trim()) {
    pathStr = '/bot/username=' + encodeURIComponent(channel.trim()) + '&password=' + encodeURIComponent(token.trim());
  } else {
    pathStr = '/chat/channel=' + encodeURIComponent(channel.trim());
  }

  const key = crypto.randomBytes(16).toString('base64');
  let closed = false;
  let handshake = false;
  let buf = Buffer.alloc(0);
  let localPingTimer = null;

  log('WebSocket接続開始: wss://' + host + pathStr);

  const socket = tls.connect(
    {
      host,
      port,
      servername: host,
      rejectUnauthorized: false,
    },
    () => {
      if (closed) return;
      log('SSL接続確立。WebSocketハンドシェイク送信中...');
      socket.write(
        'GET ' +
          pathStr +
          ' HTTP/1.1\r\n' +
          'Host: ' +
          host +
          '\r\n' +
          'Upgrade: websocket\r\n' +
          'Connection: Upgrade\r\n' +
          'Sec-WebSocket-Key: ' +
          key +
          '\r\n' +
          'Sec-WebSocket-Version: 13\r\n' +
          'Origin: https://picarto.tv\r\n' +
          'User-Agent: ' +
          UA +
          '\r\n\r\n'
      );
    }
  );
  socket.setTimeout(120000);

  const sendText = (text) => {
    if (closed || !handshake) return;
    socket.write(maskFrame(0x1, Buffer.from(text, 'utf8')));
  };

  const cleanup = () => {
    if (closed) return;
    closed = true;
    if (localPingTimer) clearInterval(localPingTimer);
    localPingTimer = null;
    try { socket.end(); } catch (_) {}
    try { socket.destroy(); } catch (_) {}
    handlers.onClose();
  };

  socket.on('timeout', cleanup);
  socket.on('error', (err) => {
    handlers.onError(err);
    cleanup();
  });
  socket.on('close', cleanup);

  socket.on('data', (chunk) => {
    if (closed) return;
    buf = Buffer.concat([buf, chunk]);

    if (!handshake) {
      const idx = buf.indexOf('\r\n\r\n');
      if (idx < 0) return;
      const head = buf.slice(0, idx).toString('utf8');
      buf = buf.slice(idx + 4);
      if (!head.includes('101')) {
        handlers.onError(new Error('WebSocketハンドシェイク拒否 (HTTP 101ではありません)'));
        cleanup();
        return;
      }
      handshake = true;
      log('101 Switching Protocols 受信！チャット待機開始');
      handlers.onOpen();

      // 30秒ごとに ping 送信
      if (!localPingTimer) {
        localPingTimer = setInterval(() => {
          if (!closed && handshake) {
            socket.write(maskFrame(0x9, Buffer.alloc(0)));
          }
        }, 30000);
      }
    }

    while (buf.length >= 2) {
      const opcode = buf[0] & 0x0f;
      let len = buf[1] & 0x7f;
      const masked = Boolean(buf[1] & 0x80);
      let off = 2;
      if (len === 126) {
        if (buf.length < 4) break;
        len = buf.readUInt16BE(2);
        off = 4;
      } else if (len === 127) {
        if (buf.length < 10) break;
        len = Number(buf.readBigUInt64BE(2));
        off = 10;
      }
      if (masked) off += 4;
      if (buf.length < off + len) break;

      let payload = buf.slice(off, off + len);
      if (masked) {
        const mask = buf.slice(off - 4, off);
        const un = Buffer.alloc(len);
        for (let i = 0; i < len; i++) un[i] = payload[i] ^ mask[i % 4];
        payload = un;
      }
      buf = buf.slice(off + len);

      if (opcode === 0x8) {
        cleanup();
        return;
      }
      if (opcode === 0x9) {
        // ping に対する pong 返送
        socket.write(maskFrame(0xa, payload));
        continue;
      }
      if (opcode !== 0x1 && opcode !== 0x2) continue;

      const rawText = payload.toString('utf8');
      try {
        const json = JSON.parse(rawText);
        handlers.onMessage(json);
      } catch (_) {
        // 非JSONパケットの場合は無視
      }
    }
  });

  return {
    close: cleanup,
    sendMessage: (msg) => {
      sendText(JSON.stringify({ type: 'chat', message: String(msg) }));
    },
  };
}

// わんコメ本体の API へコメント直接注入
function emitComment(serviceId, event) {
  if (!serviceId) return;
  seq += 1;
  const now = event.timestamp || Date.now();
  const payload = {
    service: {
      id: serviceId,
      write: true,
      speech: true,
      persist: true,
    },
    comment: {
      id: 'picarto-' + now + '-' + seq,
      userId: String(event.userId || 'picarto'),
      name: event.name || '名無し',
      badges: [],
      profileImage: event.profileImage || '',
      comment: event.comment,
      hasGift: Boolean(event.hasGift),
      isOwner: Boolean(event.isOwner),
      timestamp: now,
    },
  };

  const body = JSON.stringify(payload);
  const req = http.request(
    {
      hostname: '127.0.0.1',
      port: 11180,
      path: '/api/comments',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body, 'utf8'),
      },
    },
    (res) => {
      if (res.statusCode === 200) {
        log('わんコメへ送信完了 [OK]: ' + event.name + ': ' + event.comment);
      } else {
        let data = '';
        res.on('data', (d) => (data += d));
        res.on('end', () => log('わんコメAPIエラー: ' + res.statusCode + ' ' + data));
      }
    }
  );
  req.on('error', (e) => log('API送信エラー: ' + e.message));
  req.write(body);
  req.end();
}

function disconnect() {
  if (activeSocket) {
    log('切断処理を実行');
    try { activeSocket.close(); } catch (_) {}
    activeSocket = null;
  }
  currentServiceId = null;
  currentChannel = null;
  currentToken = null;
  connectionStatus.state = 'idle';
}

async function startPicarto(serviceId, channel, token) {
  disconnect();
  currentServiceId = serviceId;
  currentChannel = channel;
  currentToken = token;

  connectionStatus.state = 'checking';
  connectionStatus.channel = channel;
  connectionStatus.lastCheck = new Date().toISOString();

  log('配信状態確認中: チャンネル=' + channel);
  let info = null;
  try {
    info = await fetchChannelInfo(channel);
    connectionStatus.isLive = info.isLive;
    connectionStatus.title = info.title;
    log('チャンネル情報取得成功: ' + info.name + ' (配信中=' + info.isLive + ', タイトル=' + info.title + ')');
  } catch (err) {
    log('配信情報取得失敗（チャット接続を試行します）: ' + err.message);
  }

  connectionStatus.state = 'connected';

  activeSocket = connectPicartoChat(channel, token, {
    onOpen: () => {
      log('★ Picartoチャット接続完了！コメント受信スタンバイ完了');
    },
    onMessage: (json) => {
      if (json && json.t === 'authentication') {
        if (json.success) {
          log('★ Picartoボット認証成功！チャット同期が有効化されました');
          connectionStatus.state = 'connected';
        } else {
          log('認証エラー: トークンが無効です。https://oauth.picarto.tv/chat/bot で再発行してください。');
          connectionStatus.state = 'error';
          connectionStatus.error = 'Invalid token';
        }
        return;
      }
      // チャットメッセージ形式: { t: "c", m: [ { c, rn, u, n, m, a, i, k, id } ] }
      if (json && json.t === 'c' && Array.isArray(json.m)) {
        for (const item of json.m) {
          const commentText = String(item.m || '');
          if (!commentText) continue;

          const isOwner = Boolean(
            (item.n && item.n.toLowerCase() === channel.toLowerCase()) ||
            (info && info.userId && String(item.u) === String(info.userId))
          );

          const displayName = isOwner ? `${item.n} (配信者)` : item.n;

          log('受信 [' + item.n + ']: ' + commentText);
          emitComment(serviceId, {
            userId: item.u,
            name: displayName,
            comment: commentText,
            profileImage: '',
            hasGift: false,
            isOwner: false,
            timestamp: item.a ? Number(item.a) : Date.now(),
          });
        }
      } else if (json && json.code === 'JWT_TOKEN') {
        log('認証エラー: トークンが無効または未設定です。https://oauth.picarto.tv/chat/bot でトークンを発行して設定してください。');
        connectionStatus.state = 'error';
        connectionStatus.error = 'JWT_TOKEN required';
      }
    },
    onError: (err) => {
      log('チャット通信エラー: ' + err.message);
      connectionStatus.state = 'error';
      connectionStatus.error = err.message;
    },
    onClose: () => {
      log('チャット接続が切断されました');
      activeSocket = null;
      if (connectionStatus.state === 'connected') {
        connectionStatus.state = 'idle';
      }
    },
  });
}

function extractChannel(url) {
  if (!url) return '';
  const raw = String(url).trim();
  try {
    const u = raw.includes('://') ? new URL(raw) : new URL('https://' + raw);
    if (u.hostname.toLowerCase().includes('picarto.tv')) {
      const parts = u.pathname.split('/').filter(Boolean);
      if (parts.length > 0) return parts[parts.length - 1];
    }
  } catch (_) {}
  if (/^[a-zA-Z0-9_-]{2,32}$/.test(raw)) return raw;
  return '';
}

const plugin = {
  name: 'Picarto (ピカルト) コメント連携',
  uid: 'dev.orangeqoon.picarto',
  version: '1.0.0',
  author: 'orangeqoon',
  url: 'https://github.com/orangeqoon/onecomme-plugin-picarto',
  permissions: ['comments', 'services'],
  defaultState: {},

  init(ctx) {
    pluginDir = (ctx && ctx.dir) || __dirname;
    log('Picartoプラグイン起動（v1.0.0）');

    this.timer = setInterval(async () => {
      try {
        const res = await fetch('http://localhost:11180/api/services');
        if (!res.ok) return;
        const services = await res.json();

        // 枠名に picarto を含む枠、または URL に picarto を含む枠を探す
        const picartoService = services.find((s) => {
          if (!s.enabled) return false;
          const name = (s.name || '').toLowerCase();
          const u = (s.url || '').toLowerCase();
          return name.includes('picarto') || u.includes('picarto.tv');
        });

        if (!picartoService) {
          if (activeSocket || currentChannel) {
            log('Picarto枠がオフになりました。切断します。');
            disconnect();
          }
          return;
        }

        const cfg = loadConfig(pluginDir);
        let channel = extractChannel(picartoService.url) || cfg.channel || '';
        if (!channel) {
          const m = (picartoService.name || '').match(/picarto[:\s_]+([a-zA-Z0-9_-]{2,32})/i);
          if (m) channel = m[1];
        }
        if (!channel) return;

        // 内蔵ブラウザのエラー切断防止（URLが設定されていたら自動クリア）
        if (picartoService.url && picartoService.url.trim() !== '') {
          fetch('http://localhost:11180/api/services/' + picartoService.id, {
            method: 'PUT',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ...picartoService, url: '', meta: {} }),
          }).catch(() => {});
        }

        // 枠IDやチャンネルが切り替わった場合、または未接続の場合に接続開始
        if (currentChannel !== channel || currentServiceId !== picartoService.id || !activeSocket) {
          log('Picarto枠検知: ' + picartoService.name + ' (チャンネル: ' + channel + ') -> 接続処理開始');
          startPicarto(picartoService.id, channel, cfg.token || '');
        }
      } catch (_) {}
    }, 4000);
  },

  destroy() {
    if (this.timer) clearInterval(this.timer);
    disconnect();
  },

  // 内包Web設定UIとの通信ハンドラ (GET/POST /api/plugins/dev.orangeqoon.picarto)
  async request(req) {
    const method = (req.method || 'GET').toUpperCase();
    const cfg = loadConfig(pluginDir);

    if (method === 'GET') {
      return {
        status: 200,
        body: {
          config: cfg,
          connection: {
            ...connectionStatus,
            hasSocket: Boolean(activeSocket),
            currentServiceId,
          },
        },
      };
    }

    if (method === 'POST') {
      const data = req.body || {};
      if (typeof data.channel === 'string') cfg.channel = data.channel.trim();
      if (typeof data.token === 'string') cfg.token = data.token.trim();
      saveConfig(pluginDir, cfg);

      log('設定更新を受信: チャンネル=' + cfg.channel);
      if (currentServiceId && cfg.channel) {
        startPicarto(currentServiceId, cfg.channel, cfg.token || '');
      }

      return {
        status: 200,
        body: {
          success: true,
          config: cfg,
          connection: connectionStatus,
        },
      };
    }

    return { status: 405, body: { error: 'Method Not Allowed' } };
  },
};

module.exports = plugin;
