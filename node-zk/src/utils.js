const CONST = require('./const');

function makeCommKey(key, sessionId, ticks = 50) {
  let k = 0;
  const pass = Number(key) || 0;
  const sid = Number(sessionId) || 0;

  for (let i = 0; i < 32; i += 1) {
    if (pass & (1 << i)) {
      k = (k << 1) | 1;
    } else {
      k <<= 1;
    }
  }

  k += sid;
  const tmp = Buffer.allocUnsafe(4);
  tmp.writeUInt32LE(k >>> 0, 0);

  const xored = Buffer.from([
    tmp[0] ^ 'Z'.charCodeAt(0),
    tmp[1] ^ 'K'.charCodeAt(0),
    tmp[2] ^ 'S'.charCodeAt(0),
    tmp[3] ^ 'O'.charCodeAt(0)
  ]);

  const swapped = Buffer.allocUnsafe(4);
  swapped.writeUInt16LE(xored.readUInt16LE(2), 0);
  swapped.writeUInt16LE(xored.readUInt16LE(0), 2);

  const B = 0xff & ticks;
  return Buffer.from([
    swapped[0] ^ B,
    swapped[1] ^ B,
    B,
    swapped[3] ^ B
  ]);
}

function createChecksum(buffer) {
  let checksum = 0;
  let idx = 0;
  let remaining = buffer.length;

  while (remaining > 1) {
    checksum += buffer[idx] + (buffer[idx + 1] << 8);
    if (checksum > CONST.USHRT_MAX) {
      checksum -= CONST.USHRT_MAX;
    }
    idx += 2;
    remaining -= 2;
  }

  if (remaining) {
    checksum += buffer[buffer.length - 1];
  }

  while (checksum > CONST.USHRT_MAX) {
    checksum -= CONST.USHRT_MAX;
  }

  checksum = (~checksum) & 0xffff;
  return checksum;
}

function createHeader(command, commandString, sessionId, replyId) {
  const header = Buffer.allocUnsafe(8);
  header.writeUInt16LE(command, 0);
  header.writeUInt16LE(0, 2); // placeholder for checksum
  header.writeUInt16LE(sessionId, 4);

  let nextReplyId = replyId + 1;
  if (nextReplyId >= CONST.USHRT_MAX) {
    nextReplyId -= CONST.USHRT_MAX;
  }
  header.writeUInt16LE(nextReplyId, 6);

  const merged = Buffer.concat([header, commandString]);
  const checksum = createChecksum(merged);
  header.writeUInt16LE(checksum, 2);

  return Buffer.concat([header, commandString]);
}

function createTcpTop(packet) {
  const top = Buffer.allocUnsafe(8);
  top.writeUInt16LE(CONST.MACHINE_PREPARE_DATA_1, 0);
  top.writeUInt16LE(CONST.MACHINE_PREPARE_DATA_2, 2);
  top.writeUInt32LE(packet.length, 4);
  return Buffer.concat([top, packet]);
}

function decodeTime(buffer) {
  const raw = buffer.readUInt32LE(0);
  let t = raw;
  const second = t % 60;
  t = Math.floor(t / 60);

  const minute = t % 60;
  t = Math.floor(t / 60);

  const hour = t % 24;
  t = Math.floor(t / 24);

  const day = (t % 31) + 1;
  t = Math.floor(t / 31);

  const month = (t % 12) + 1;
  const year = Math.floor(t / 12) + 2000;

  return new Date(year, month - 1, day, hour, minute, second);
}

function encodeTime(date) {
  const dt = date instanceof Date ? date : new Date(date);
  const year = dt.getFullYear() % 100;
  const month = dt.getMonth() + 1;
  const day = dt.getDate();
  const hour = dt.getHours();
  const minute = dt.getMinutes();
  const second = dt.getSeconds();

  const d = ((year * 12 * 31) + ((month - 1) * 31) + day - 1) *
    (24 * 60 * 60) + (hour * 60 + minute) * 60 + second;
  return d >>> 0;
}

function readHeader(buffer) {
  return [
    buffer.readUInt16LE(0),
    buffer.readUInt16LE(2),
    buffer.readUInt16LE(4),
    buffer.readUInt16LE(6)
  ];
}

module.exports = {
  createChecksum,
  createHeader,
  createTcpTop,
  decodeTime,
  encodeTime,
  makeCommKey,
  readHeader
};
