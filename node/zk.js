'use strict';

const net = require('net');
const dgram = require('dgram');
const os = require('os');
const { spawnSync } = require('child_process');

const consts = require('./constants');
const User = require('./user');

function safeCast(value, caster, defaultValue = null) {
  try {
    return caster(value);
  } catch (err) {
    return defaultValue;
  }
}

function makeCommKey(key, sessionId, ticks = 50) {
  const keyVal = Number(key || 0);
  let k = 0;
  for (let i = 0; i < 32; i += 1) {
    if (keyVal & (1 << i)) {
      k = (k << 1) | 1;
    } else {
      k <<= 1;
    }
  }
  k += Number(sessionId || 0);
  const tmp = Buffer.alloc(4);
  tmp.writeUInt32LE(k >>> 0, 0);
  const arr = Buffer.from([
    tmp[0] ^ 'Z'.charCodeAt(0),
    tmp[1] ^ 'K'.charCodeAt(0),
    tmp[2] ^ 'S'.charCodeAt(0),
    tmp[3] ^ 'O'.charCodeAt(0)
  ]);
  const swap = Buffer.alloc(4);
  swap.writeUInt16LE(arr.readUInt16LE(2), 0);
  swap.writeUInt16LE(arr.readUInt16LE(0), 2);
  const B = ticks & 0xff;
  return Buffer.from([
    swap[0] ^ B,
    swap[1] ^ B,
    B,
    swap[3] ^ B
  ]);
}

class ZKHelper {
  constructor(ip, port = 4370) {
    this.ip = ip;
    this.port = port;
  }

  testPing() {
    const platform = os.platform();
    const isWindows = platform.startsWith('win');
    const args = isWindows ? ['-n', '1', this.ip] : ['-c', '1', '-W', '5', this.ip];
    const result = spawnSync('ping', args, { stdio: 'ignore' });
    return result.status === 0;
  }

  testTcp(timeoutMs = 10000) {
    return new Promise((resolve) => {
      const client = new net.Socket();
      let settled = false;
      const done = (code) => {
        if (!settled) {
          settled = true;
          client.destroy();
          resolve(code);
        }
      };
      client.setTimeout(timeoutMs);
      client.once('connect', () => done(0));
      client.once('timeout', () => done(-1));
      client.once('error', () => done(-1));
      client.connect(this.port, this.ip);
    });
  }
}

class ZK {
  constructor(ip, port = 4370, timeout = 60, password = 0, forceUdp = false, ommitPing = false, verbose = false, encoding = 'UTF-8') {
    User.encoding = encoding;
    this.ip = ip;
    this.port = port;
    this.__address = { ip, port };
    this.__timeout = timeout;
    this.__password = password;
    this.__session_id = 0;
    this.__reply_id = consts.USHRT_MAX - 1;
    this.__sock = null;
    this.__tcpBuffer = Buffer.alloc(0);
    this.__tcpWaiters = [];
    this.__udpQueue = [];
    this.__udpWaiters = [];
    this.__header = null;
    this.__response = null;
    this.__data_recv = null;
    this.__data = null;
    this.__tcp_length = 0;
    this.is_connect = false;
    this.is_enabled = true;
    this.helper = new ZKHelper(ip, port);
    this.force_udp = forceUdp;
    this.ommit_ping = ommitPing;
    this.verbose = verbose;
    this.encoding = encoding;
    this.tcp = !forceUdp;
    this.users = 0;
    this.fingers = 0;
    this.records = 0;
    this.dummy = 0;
    this.cards = 0;
    this.fingers_cap = 0;
    this.users_cap = 0;
    this.rec_cap = 0;
    this.faces = 0;
    this.faces_cap = 0;
    this.fingers_av = 0;
    this.users_av = 0;
    this.rec_av = 0;
    this.next_uid = 1;
    this.next_user_id = '1';
    this.user_packet_size = 28;
    this.end_live_capture = false;
  }

  async connect() {
    this.end_live_capture = false;
    if (!this.ommit_ping && !this.helper.testPing()) {
      throw new Error(`can't reach device (ping ${this.__address.ip || this.ip})`);
    }
    if (!this.force_udp) {
      const tcpResult = await this.helper.testTcp();
      if (tcpResult === 0) {
        this.user_packet_size = 72;
      }
    }
    await this.__create_socket();
    this.__session_id = 0;
    this.__reply_id = consts.USHRT_MAX - 1;
    const response = await this.__send_command(consts.CMD_CONNECT);
    this.__session_id = this.__header.sessionId;
    if (response.code === consts.CMD_ACK_UNAUTH) {
      if (this.verbose) console.log('try auth');
      const commandString = makeCommKey(this.__password, this.__session_id);
      await this.__send_command(consts.CMD_AUTH, commandString);
    }
    if (response.status) {
      this.is_connect = true;
      return this;
    }
    if (response.code === consts.CMD_ACK_UNAUTH) {
      throw new Error('Unauthenticated');
    }
    throw new Error('Invalid response: Can\'t connect');
  }

  async disconnect() {
    const cmd = await this.__send_command(consts.CMD_EXIT);
    if (cmd.status) {
      this.is_connect = false;
      if (this.__sock) {
        if (this.tcp) {
          this.__sock.end();
        } else {
          this.__sock.close();
        }
      }
      return true;
    }
    throw new Error("can't disconnect");
  }

  async enable_device() {
    const cmd = await this.__send_command(consts.CMD_ENABLEDEVICE);
    if (cmd.status) {
      this.is_enabled = true;
      return true;
    }
    throw new Error("Can't enable device");
  }

  async disable_device() {
    const cmd = await this.__send_command(consts.CMD_DISABLEDEVICE);
    if (cmd.status) {
      this.is_enabled = false;
      return true;
    }
    throw new Error("Can't disable device");
  }

  async free_data() {
    const cmd = await this.__send_command(consts.CMD_FREE_DATA);
    if (cmd.status) {
      return true;
    }
    throw new Error("can't free data");
  }

  async read_sizes() {
    const cmd = await this.__send_command(consts.CMD_GET_FREE_SIZES, Buffer.alloc(0), 1024);
    if (!cmd.status) {
      throw new Error("can't read sizes");
    }
    if (this.verbose) console.log(this.__data.toString('hex'));
    if (this.__data.length >= 80) {
      const fields = [];
      for (let i = 0; i < 20; i += 1) {
        fields.push(this.__data.readInt32LE(i * 4));
      }
      this.users = fields[4];
      this.fingers = fields[6];
      this.records = fields[8];
      this.dummy = fields[10];
      this.cards = fields[12];
      this.fingers_cap = fields[14];
      this.users_cap = fields[15];
      this.rec_cap = fields[16];
      this.fingers_av = fields[17];
      this.users_av = fields[18];
      this.rec_av = fields[19];
      this.__data = this.__data.slice(80);
    }
    if (this.__data.length >= 12) {
      const faces = this.__data.readInt32LE(0);
      const facesCap = this.__data.readInt32LE(8);
      this.faces = faces;
      this.faces_cap = facesCap;
    }
    return true;
  }

  async read_with_buffer(command, fct = 0, ext = 0) {
    const maxChunk = this.tcp ? 0xffc0 : 16 * 1024;
    const commandString = Buffer.alloc(11);
    commandString.writeInt8(1, 0);
    commandString.writeInt16LE(command, 1);
    commandString.writeInt32LE(fct, 3);
    commandString.writeInt32LE(ext, 7);
    const data = [];
    let start = 0;
    const cmd = await this.__send_command(consts._CMD_PREPARE_BUFFER, commandString, 1024);
    if (!cmd.status) {
      throw new Error('RWB Not supported');
    }
    if (cmd.code === consts.CMD_DATA) {
      if (this.tcp) {
        if (this.verbose) {
          console.log(`DATA! is ${this.__data.length} bytes, tcp length is ${this.__tcp_length}`);
        }
        const need = (this.__tcp_length - 8) - this.__data.length;
        if (need > 0) {
          if (this.verbose) console.log(`need more data: ${need}`);
          const more = await this.__recieve_raw_data(need);
          return { buffer: Buffer.concat([this.__data, more]), size: this.__data.length + more.length };
        }
        if (this.verbose) console.log('Enough data');
        return { buffer: this.__data, size: this.__data.length };
      }
      return { buffer: this.__data, size: this.__data.length };
    }
    const size = this.__data.readUInt32LE(1);
    if (this.verbose) console.log(`size fill be ${size}`);
    const remain = size % maxChunk;
    const packets = Math.floor((size - remain) / maxChunk);
    if (this.verbose) {
      console.log(`rwb: #${packets} packets of max ${maxChunk} bytes, and extra ${remain} bytes remain`);
    }
    for (let i = 0; i < packets; i += 1) {
      const chunk = await this.__read_chunk(start, maxChunk);
      data.push(chunk);
      start += maxChunk;
    }
    if (remain) {
      const chunk = await this.__read_chunk(start, remain);
      data.push(chunk);
      start += remain;
    }
    await this.free_data();
    if (this.verbose) console.log(`_read w/chunk ${start} bytes`);
    return { buffer: Buffer.concat(data), size: start };
  }

  async get_users() {
    await this.read_sizes();
    if (this.users === 0) {
      this.next_uid = 1;
      this.next_user_id = '1';
      return [];
    }
    const users = [];
    let maxUid = 0;
    const { buffer: userdata, size } = await this.read_with_buffer(consts.CMD_USERTEMP_RRQ, consts.FCT_USER);
    if (this.verbose) console.log(`user size ${size} (= ${userdata.length})`);
    if (size <= 4) {
      if (this.verbose) console.log('WRN: missing user data');
      return [];
    }
    const totalSize = userdata.readUInt32LE(0);
    this.user_packet_size = totalSize / this.users;
    if (![28, 72].includes(this.user_packet_size)) {
      if (this.verbose) console.log(`WRN packet size would be ${this.user_packet_size}`);
    }
    let remaining = userdata.slice(4);
    if (this.user_packet_size === 28) {
      while (remaining.length >= 28) {
        const block = Buffer.from(remaining.slice(0, 28));
        const uid = block.readUInt16LE(0);
        const privilege = block.readUInt8(2);
        const password = block.slice(3, 8).toString(this.encoding).split('\x00')[0];
        const name = block.slice(8, 16).toString(this.encoding).split('\x00')[0].trim();
        const card = block.readUInt32LE(16);
        const groupId = `${block.readUInt16LE(20)}`;
        const userId = `${block.readUInt32LE(24)}`;
        if (uid > maxUid) maxUid = uid;
        const resolvedName = name || `NN-${userId}`;
        const user = new User(uid, resolvedName, privilege, password, groupId, userId, card, this.encoding);
        users.push(user);
        if (this.verbose) console.log('[6]user:', uid, privilege, password, resolvedName, card, groupId, 0, userId);
        remaining = remaining.slice(28);
      }
    } else {
      while (remaining.length >= 72) {
        const block = Buffer.from(remaining.slice(0, 72));
        const uid = block.readUInt16LE(0);
        const privilege = block.readUInt8(2);
        const password = block.slice(3, 11).toString(this.encoding).split('\x00')[0];
        const name = block.slice(11, 35).toString(this.encoding).split('\x00')[0].trim();
        const card = block.readUInt32LE(35);
        const groupId = block.slice(40, 47).toString(this.encoding).split('\x00')[0].trim();
        const userId = block.slice(48, 72).toString(this.encoding).split('\x00')[0];
        if (uid > maxUid) maxUid = uid;
        const resolvedName = name || `NN-${userId}`;
        const user = new User(uid, resolvedName, privilege, password, groupId, userId, card, this.encoding);
        users.push(user);
        remaining = remaining.slice(72);
      }
    }
    maxUid += 1;
    this.next_uid = maxUid;
    this.next_user_id = `${maxUid}`;
    while (users.some((u) => u.userId === this.next_user_id)) {
      maxUid += 1;
      this.next_user_id = `${maxUid}`;
    }
    return users;
  }

  async getUsers() {
    return this.get_users();
  }

  async __create_socket() {
    if (this.tcp) {
      this.__sock = new net.Socket();
      this.__sock.setTimeout(this.__timeout * 1000);
      this.__tcpBuffer = Buffer.alloc(0);
      this.__tcpWaiters = [];
      this.__sock.on('data', (chunk) => {
        this.__tcpBuffer = Buffer.concat([this.__tcpBuffer, chunk]);
        if (this.__tcpWaiters.length) {
          const waiter = this.__tcpWaiters.shift();
          waiter.resolve();
        }
      });
      const failWaiters = (err) => {
        while (this.__tcpWaiters.length) {
          const waiter = this.__tcpWaiters.shift();
          waiter.reject(err);
        }
      };
      this.__sock.on('error', failWaiters);
      this.__sock.on('close', () => failWaiters(new Error('TCP socket closed')));
      this.__sock.on('timeout', () => failWaiters(new Error('TCP socket timeout')));
      await new Promise((resolve, reject) => {
        const onError = (err) => {
          cleanup();
          reject(err);
        };
        const onConnect = () => {
          cleanup();
          resolve();
        };
        const cleanup = () => {
          this.__sock.removeListener('error', onError);
          this.__sock.removeListener('connect', onConnect);
        };
        this.__sock.once('error', onError);
        this.__sock.once('connect', onConnect);
        this.__sock.connect(this.port, this.ip);
      });
    } else {
      this.__sock = dgram.createSocket('udp4');
      this.__udpQueue = [];
      this.__udpWaiters = [];
      this.__sock.on('message', (msg) => {
        if (this.__udpWaiters.length) {
          const waiter = this.__udpWaiters.shift();
          waiter.resolve(msg);
        } else {
          this.__udpQueue.push(msg);
        }
      });
      this.__sock.on('error', (err) => {
        while (this.__udpWaiters.length) {
          const waiter = this.__udpWaiters.shift();
          waiter.reject(err);
        }
      });
    }
  }

  __create_tcp_top(packet) {
    const top = Buffer.alloc(8);
    top.writeUInt16LE(consts.MACHINE_PREPARE_DATA_1, 0);
    top.writeUInt16LE(consts.MACHINE_PREPARE_DATA_2, 2);
    top.writeUInt32LE(packet.length, 4);
    return Buffer.concat([top, packet]);
  }

  __unpack_header(buffer) {
    return {
      command: buffer.readUInt16LE(0),
      checksum: buffer.readUInt16LE(2),
      sessionId: buffer.readUInt16LE(4),
      replyId: buffer.readUInt16LE(6)
    };
  }

  __create_header(command, commandString, sessionId, replyId) {
    const payload = Buffer.alloc(8 + commandString.length);
    payload.writeUInt16LE(command, 0);
    payload.writeUInt16LE(0, 2);
    payload.writeUInt16LE(sessionId, 4);
    payload.writeUInt16LE(replyId, 6);
    commandString.copy(payload, 8);
    const checksum = this.__create_checksum(payload);
    let nextReply = replyId + 1;
    if (nextReply >= consts.USHRT_MAX) {
      nextReply -= consts.USHRT_MAX;
    }
    const header = Buffer.alloc(8 + commandString.length);
    header.writeUInt16LE(command, 0);
    header.writeUInt16LE(checksum, 2);
    header.writeUInt16LE(sessionId, 4);
    header.writeUInt16LE(nextReply, 6);
    commandString.copy(header, 8);
    return header;
  }

  __create_checksum(buffer) {
    let checksum = 0;
    let length = buffer.length;
    let index = 0;
    while (length > 1) {
      const value = buffer[index] | (buffer[index + 1] << 8);
      checksum += value;
      if (checksum > consts.USHRT_MAX) {
        checksum -= consts.USHRT_MAX;
      }
      index += 2;
      length -= 2;
    }
    if (length) {
      checksum += buffer[buffer.length - 1];
    }
    while (checksum > consts.USHRT_MAX) {
      checksum -= consts.USHRT_MAX;
    }
    checksum = ~checksum;
    while (checksum < 0) {
      checksum += consts.USHRT_MAX;
    }
    return checksum & 0xffff;
  }

  __test_tcp_top(packet) {
    if (packet.length <= 8) {
      return 0;
    }
    const first = packet.readUInt16LE(0);
    const second = packet.readUInt16LE(2);
    if (first === consts.MACHINE_PREPARE_DATA_1 && second === consts.MACHINE_PREPARE_DATA_2) {
      return packet.readUInt32LE(4);
    }
    return 0;
  }

  async __send_command(command, commandString = Buffer.alloc(0), responseSize = 8) {
    if (!Buffer.isBuffer(commandString)) {
      commandString = Buffer.from(commandString);
    }
    if (![consts.CMD_CONNECT, consts.CMD_AUTH].includes(command) && !this.is_connect) {
      throw new Error('instance are not connected.');
    }
    const header = this.__create_header(command, commandString, this.__session_id, this.__reply_id);
    try {
      if (this.tcp) {
        const packet = this.__create_tcp_top(header);
        await this.__write_tcp(packet);
        const response = await this.__read_tcp(responseSize + 8);
        this.__tcp_length = this.__test_tcp_top(response);
        if (!this.__tcp_length) {
          throw new Error('TCP packet invalid');
        }
        this.__data_recv = response.slice(8);
        this.__header = this.__unpack_header(this.__data_recv.slice(0, 8));
      } else {
        await this.__send_udp(header);
        const response = await this.__receive_udp();
        this.__data_recv = response;
        this.__header = this.__unpack_header(this.__data_recv.slice(0, 8));
      }
    } catch (err) {
      throw err;
    }
    this.__response = this.__header.command;
    this.__reply_id = this.__header.replyId;
    this.__data = this.__data_recv.slice(8);
    if ([consts.CMD_ACK_OK, consts.CMD_PREPARE_DATA, consts.CMD_DATA].includes(this.__response)) {
      return { status: true, code: this.__response };
    }
    return { status: false, code: this.__response };
  }

  async __write_tcp(buffer) {
    return new Promise((resolve, reject) => {
      const onError = (err) => {
        cleanup();
        reject(err);
      };
      const cleanup = () => {
        this.__sock.removeListener('error', onError);
      };
      this.__sock.once('error', onError);
      this.__sock.write(buffer, () => {
        cleanup();
        resolve();
      });
    });
  }

  async __read_tcp(length) {
    const deadline = Date.now() + this.__timeout * 1000;
    while (this.__tcpBuffer.length < length) {
      await this.__wait_for_tcp(deadline);
    }
    const chunk = this.__tcpBuffer.slice(0, length);
    this.__tcpBuffer = this.__tcpBuffer.slice(length);
    return chunk;
  }

  __wait_for_tcp(deadlineMs) {
    return new Promise((resolve, reject) => {
      const remaining = deadlineMs - Date.now();
      if (remaining <= 0) {
        reject(new Error('TCP receive timeout'));
        return;
      }
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('TCP receive timeout'));
      }, remaining);
      const cleanup = () => {
        clearTimeout(timer);
        const idx = this.__tcpWaiters.indexOf(entry);
        if (idx >= 0) {
          this.__tcpWaiters.splice(idx, 1);
        }
      };
      const entry = {
        resolve: () => {
          cleanup();
          resolve();
        },
        reject: (err) => {
          cleanup();
          reject(err);
        }
      };
      this.__tcpWaiters.push(entry);
    });
  }

  async __send_udp(buffer) {
    return new Promise((resolve, reject) => {
      this.__sock.send(buffer, this.port, this.ip, (err) => {
        if (err) {
          reject(err);
          return;
        }
        resolve();
      });
    });
  }

  async __receive_udp() {
    if (this.__udpQueue.length) {
      return this.__udpQueue.shift();
    }
    const timeoutMs = this.__timeout * 1000;
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('UDP receive timeout'));
      }, timeoutMs);
      const cleanup = () => {
        clearTimeout(timer);
        const idx = this.__udpWaiters.indexOf(entry);
        if (idx >= 0) {
          this.__udpWaiters.splice(idx, 1);
        }
      };
      const entry = {
        resolve: (msg) => {
          cleanup();
          resolve(msg);
        },
        reject: (err) => {
          cleanup();
          reject(err);
        }
      };
      this.__udpWaiters.push(entry);
    });
  }

  __get_data_size() {
    if (this.__response === consts.CMD_PREPARE_DATA) {
      return this.__data.readUInt32LE(0);
    }
    return 0;
  }

  async __recieve_raw_data(size) {
    if (!size) {
      return Buffer.alloc(0);
    }
    if (this.verbose) console.log(`expecting ${size} bytes raw data`);
    const data = await this.__read_tcp(size);
    if (this.verbose) console.log(`partial recv ${data.length}`);
    return data;
  }

  async __recieve_tcp_data(dataRecv, size) {
    const parts = [];
    const tcpLength = this.__test_tcp_top(dataRecv);
    if (this.verbose) console.log(`tcp_length ${tcpLength}, size ${size}`);
    if (tcpLength <= 0) {
      if (this.verbose) console.log('Incorrect tcp packet');
      return { data: null, broken: Buffer.alloc(0) };
    }
    if ((tcpLength - 8) < size) {
      if (this.verbose) console.log('tcp length too small... retrying');
      const first = await this.__recieve_tcp_data(dataRecv, tcpLength - 8);
      if (!first.data) {
        return { data: null, broken: Buffer.alloc(0) };
      }
      parts.push(first.data);
      size -= first.data.length;
      if (this.verbose) console.log(`new tcp DATA packet to fill misssing ${size}`);
      let buffer = first.broken;
      const need = size + 16 - buffer.length;
      if (need > 0) {
        const extra = await this.__read_tcp(need);
        buffer = Buffer.concat([buffer, extra]);
      }
      if (this.verbose) console.log(`new tcp DATA starting with ${buffer.length} bytes`);
      const second = await this.__recieve_tcp_data(buffer, size);
      if (!second.data) {
        return { data: null, broken: Buffer.alloc(0) };
      }
      parts.push(second.data);
      if (this.verbose) {
        console.log(`for misssing ${size} recieved ${second.data.length} with extra ${second.broken.length}`);
      }
      return { data: Buffer.concat(parts), broken: second.broken };
    }
    const received = dataRecv.length;
    if (this.verbose) console.log(`recieved ${received}, size ${size}`);
    const response = dataRecv.readUInt16LE(8);
    if (received >= (size + 32)) {
      if (response === consts.CMD_DATA) {
        const resp = dataRecv.slice(16, size + 16);
        if (this.verbose) console.log(`resp complete len ${resp.length}`);
        return { data: resp, broken: dataRecv.slice(size + 16) };
      }
      if (this.verbose) console.log(`incorrect response!!! ${response}`);
      return { data: null, broken: Buffer.alloc(0) };
    }
    if (this.verbose) console.log(`try DATA incomplete (actual valid ${received - 16})`);
    const chunk = dataRecv.slice(16, size + 16);
    parts.push(chunk);
    let remaining = size - (received - 16);
    let brokenHeader = Buffer.alloc(0);
    if (remaining < 0) {
      brokenHeader = dataRecv.slice(dataRecv.length + remaining);
      remaining = 0;
      if (this.verbose && brokenHeader.length) {
        console.log(`broken ${brokenHeader.toString('hex')}`);
      }
    }
    if (remaining > 0) {
      const extra = await this.__recieve_raw_data(remaining);
      parts.push(extra);
    }
    return { data: Buffer.concat(parts), broken: brokenHeader };
  }

  async __recieve_chunk() {
    if (this.__response === consts.CMD_DATA) {
      if (this.tcp) {
        if (this.verbose) {
          console.log(`_rc_DATA! is ${this.__data.length} bytes, tcp length is ${this.__tcp_length}`);
        }
        const need = (this.__tcp_length - 8) - this.__data.length;
        if (need > 0) {
          if (this.verbose) console.log(`need more data: ${need}`);
          const more = await this.__recieve_raw_data(need);
          return Buffer.concat([this.__data, more]);
        }
        if (this.verbose) console.log('Enough data');
        return this.__data;
      }
      if (this.verbose) console.log(`_rc len is ${this.__data.length}`);
      return this.__data;
    }
    if (this.__response === consts.CMD_PREPARE_DATA) {
      const data = [];
      let size = this.__get_data_size();
      if (this.verbose) console.log(`recieve chunk: prepare data size is ${size}`);
      if (this.tcp) {
        let dataRecv;
        if (this.__data.length >= (8 + size)) {
          dataRecv = this.__data.slice(8);
        } else {
          const extra = await this.__read_tcp(size + 32 - (this.__data.length - 8));
          dataRecv = Buffer.concat([this.__data.slice(8), extra]);
        }
        const { data: resp, broken } = await this.__recieve_tcp_data(dataRecv, size);
        if (!resp) {
          return null;
        }
        data.push(resp);
        let ackPacket = broken;
        if (ackPacket.length < 16) {
          const extra = await this.__read_tcp(16 - ackPacket.length);
          ackPacket = Buffer.concat([ackPacket, extra]);
        }
        if (!this.__test_tcp_top(ackPacket)) {
          if (this.verbose) console.log('invalid chunk tcp ACK OK');
          return null;
        }
        const response = ackPacket.readUInt16LE(8);
        if (response === consts.CMD_ACK_OK) {
          if (this.verbose) console.log('chunk tcp ACK OK!');
          return Buffer.concat(data);
        }
        if (this.verbose) console.log('bad response %s', ackPacket.toString('hex'));
        if (this.verbose) console.log(Buffer.concat(data).toString('hex'));
        return null;
      }
      while (true) {
        const packet = await this.__receive_udp();
        const response = packet.readUInt16LE(0);
        if (this.verbose) console.log(`# packet response is: ${response}`);
        if (response === consts.CMD_DATA) {
          data.push(packet.slice(8));
          size -= 1024;
        } else if (response === consts.CMD_ACK_OK) {
          break;
        } else {
          if (this.verbose) console.log('broken!');
          break;
        }
        if (this.verbose) console.log(`still needs ${size}`);
      }
      return Buffer.concat(data);
    }
    if (this.verbose) console.log(`invalid response ${this.__response}`);
    return null;
  }

  async __read_chunk(start, size) {
    for (let i = 0; i < 3; i += 1) {
      const commandString = Buffer.alloc(8);
      commandString.writeInt32LE(start, 0);
      commandString.writeInt32LE(size, 4);
      const responseSize = this.tcp ? size + 32 : 1024 + 8;
      await this.__send_command(consts._CMD_READ_BUFFER, commandString, responseSize);
      const data = await this.__recieve_chunk();
      if (data) {
        return data;
      }
    }
    throw new Error(`can't read chunk ${start}:[${size}]`);
  }
}

module.exports = {
  ZK,
  consts,
  User
};
