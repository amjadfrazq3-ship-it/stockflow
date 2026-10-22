'use strict';
// Minimal SMTP sender (no external packages). Supports implicit TLS (port 465),
// STARTTLS (port 587/25) and AUTH LOGIN.
const net = require('net');
const tls = require('tls');
const crypto = require('crypto');

function bareAddress(s) {
  const m = String(s).match(/<([^>]+)>/);
  return (m ? m[1] : String(s)).trim();
}
function encodeHeader(s) {
  return /^[\x20-\x7e]*$/.test(s) ? s : '=?UTF-8?B?' + Buffer.from(s, 'utf8').toString('base64') + '?=';
}

function sendMail(cfg, { to, subject, text }) {
  return new Promise((resolve, reject) => {
    const secure = !!cfg.secure;
    let sock = null, buf = '', pending = null, finished = false;
    const timer = setTimeout(() => fail(new Error('SMTP timed out')), 20000);

    function fail(err) {
      if (finished) return;
      finished = true; clearTimeout(timer);
      try { sock && sock.destroy(); } catch (_) {}
      reject(err);
    }
    function succeed() {
      if (finished) return;
      finished = true; clearTimeout(timer);
      try { sock && sock.end(); } catch (_) {}
      resolve();
    }
    function attach(s) {
      sock = s; buf = '';
      s.setEncoding('utf8');
      s.on('data', d => { buf += d; flush(); });
      s.on('error', fail);
      s.on('close', () => { if (!finished) fail(new Error('SMTP connection closed')); });
    }
    // Reads one complete reply (handles multi-line replies such as 250-...).
    function reply() {
      return new Promise((res, rej) => { pending = { res, rej }; flush(); });
    }
    function flush() {
      if (!pending) return;
      const lines = [];
      let pos = 0;
      for (;;) {
        const nl = buf.indexOf('\r\n', pos);
        if (nl < 0) return;
        const line = buf.slice(pos, nl);
        pos = nl + 2;
        lines.push(line);
        if (/^\d{3} /.test(line)) {
          buf = buf.slice(pos);
          const p = pending; pending = null;
          return p.res({ code: Number(line.slice(0, 3)), lines });
        }
      }
    }
    async function cmd(line, okCodes) {
      sock.write(line + '\r\n');
      const r = await reply();
      if (!okCodes.includes(r.code)) throw new Error('SMTP ' + line.split(' ')[0] + ' failed: ' + r.lines.join(' | '));
      return r;
    }

    async function main() {
      attach(secure
        ? tls.connect({ host: cfg.host, port: cfg.port, servername: cfg.host, rejectUnauthorized: cfg.rejectUnauthorized !== false })
        : net.connect({ host: cfg.host, port: cfg.port }));
      if (secure) await new Promise((res, rej) => { sock.once('secureConnect', res); sock.once('error', rej); });
      const greet = await reply();
      if (greet.code !== 220) throw new Error('SMTP greeting failed: ' + greet.lines.join(' | '));
      let ehlo = await cmd('EHLO stockflow.local', [250]);
      if (!secure && /STARTTLS/i.test(ehlo.lines.join('\n'))) {
        await cmd('STARTTLS', [220]);
        const plain = sock;
        plain.removeAllListeners('data');
        const upgraded = tls.connect({ socket: plain, servername: cfg.host, rejectUnauthorized: cfg.rejectUnauthorized !== false });
        await new Promise((res, rej) => { upgraded.once('secureConnect', res); upgraded.once('error', rej); });
        attach(upgraded);
        ehlo = await cmd('EHLO stockflow.local', [250]);
      }
      if (cfg.user) {
        await cmd('AUTH LOGIN', [334]);
        await cmd(Buffer.from(cfg.user).toString('base64'), [334]);
        await cmd(Buffer.from(cfg.pass || '').toString('base64'), [235]);
      }
      await cmd('MAIL FROM:<' + bareAddress(cfg.from) + '>', [250]);
      await cmd('RCPT TO:<' + bareAddress(to) + '>', [250, 251]);
      await cmd('DATA', [354]);
      const headers = [
        'From: ' + cfg.from,
        'To: ' + to,
        'Subject: ' + encodeHeader(subject),
        'Date: ' + new Date().toUTCString(),
        'Message-ID: <' + crypto.randomUUID() + '@' + (cfg.host || 'localhost') + '>',
        'MIME-Version: 1.0',
        'Content-Type: text/plain; charset=utf-8',
        'Content-Transfer-Encoding: 8bit',
      ];
      const body = String(text).replace(/\r?\n/g, '\r\n').replace(/^\./gm, '..');
      sock.write(headers.join('\r\n') + '\r\n\r\n' + body + '\r\n.\r\n');
      const done = await reply();
      if (done.code !== 250) throw new Error('SMTP message rejected: ' + done.lines.join(' | '));
      await cmd('QUIT', [221]).catch(() => {});
      succeed();
    }
    main().catch(fail);
  });
}

module.exports = { sendMail };
