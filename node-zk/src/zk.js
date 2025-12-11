const net = require('net');
const dgram = require('dgram');
const CONST = require('./const');
const {
  createHeader,
  createTcpTop,
  decodeTime,
  encodeTime,
  makeCommKey,
  readHeader
} = require('./utils');

class ZK {
  constructor({ ip, port = 4370, timeout = 60000, password = 0, forceUdp = false, verbose = false } = {}) {
    if (!ip) {
      throw new Error('Device IP is required');
    }
    this.ip = ip;
    this.port = port;
    this.timeout = timeout;
    this.password = Number(password) || 0;
    this.forceUdp = forceUdp;
    this.verbose = verbose;
    this.tcp = !forceUdp;

    this.sessionId = 0;
    this.replyId = CONST.USHRT_MAX - 1;
    this.socket = null;
    this.isConnected = false;

    this.usersCount = 0;
    this.recordsCount = 0;
    this.userPacketSize = 28; // default zk6
    this.nextUid = 1;
    this.nextUserId = '1';
  }

  log(msg) {
    if (this.verbose) {
      // eslint-disable-next-line no-console
      console.log(`[zk] ${msg}`);
    }
  }

  static _trimString(buf, start, end) {
    return buf.slice(start, end).toString('utf8').split('\x00')[0].trim();
  }

  async connect() {
    if (this.isConnected) {
      return this;
    }
    await this._createSocket();
    this.sessionId = 0;
    this.replyId = CONST.USHRT_MAX - 1;

    let response = await this._sendCommand(CONST.CMD_CONNECT);
    this.sessionId = response.header[2];

    if (response.code === CONST.CMD_ACK_UNAUTH) {
      const authPayload = makeCommKey(this.password, this.sessionId);
      response = await this._sendCommand(CONST.CMD_AUTH, authPayload);
    }

    if (!response.status && response.code !== CONST.CMD_ACK_OK) {
      throw new Error(`Invalid response while connecting (${response.code})`);
    }
    this.isConnected = true;
    this.log('connected');
    return this;
  }

  async disconnect() {
    if (!this.socket) {
      return true;
    }
    try {
      await this._sendCommand(CONST.CMD_EXIT);
    } catch (err) {
      // continue closing socket
      this.log(`disconnect warning: ${err.message}`);
    }
    await this._closeSocket();
    this.isConnected = false;
    return true;
  }

  async enableDevice() {
    const res = await this._sendCommand(CONST.CMD_ENABLEDEVICE);
    if (!res.status) {
      throw new Error('Cannot enable device');
    }
    return true;
  }

  async disableDevice() {
    const res = await this._sendCommand(CONST.CMD_DISABLEDEVICE);
    if (!res.status) {
      throw new Error('Cannot disable device');
    }
    return true;
  }

  async getTime() {
    const res = await this._sendCommand(CONST.CMD_GET_TIME, Buffer.alloc(0), 1032);
    if (!res.status) {
      throw new Error('Cannot get time');
    }
    return decodeTime(res.data.slice(0, 4));
  }

  async setTime(date) {
    const encoded = encodeTime(date);
    const payload = Buffer.allocUnsafe(4);
    payload.writeUInt32LE(encoded, 0);
    const res = await this._sendCommand(CONST.CMD_SET_TIME, payload);
    if (!res.status) {
      throw new Error('Cannot set time');
    }
    return true;
  }

  async testVoice(index = 0) {
    const payload = Buffer.allocUnsafe(4);
    payload.writeUInt32LE(index >>> 0, 0);
    const res = await this._sendCommand(CONST.CMD_TESTVOICE, payload);
    return Boolean(res.status);
  }

  async restart() {
    const res = await this._sendCommand(CONST.CMD_RESTART);
    if (!res.status) {
      throw new Error('Cannot restart device');
    }
    this.isConnected = false;
    return true;
  }

  async powerOff() {
    const res = await this._sendCommand(CONST.CMD_POWEROFF);
    if (!res.status) {
      throw new Error('Cannot power off device');
    }
    this.isConnected = false;
    return true;
  }

  async readSizes() {
    const res = await this._sendCommand(CONST.CMD_GET_FREE_SIZES, Buffer.alloc(0), 1024);
    if (!res.status) {
      throw new Error('Cannot read sizes');
    }
    const data = res.data || Buffer.alloc(0);
    if (data.length >= 80) {
      // 20 ints (4 bytes each)
      const fields = [];
      for (let i = 0; i < 20; i += 1) {
        fields.push(data.readInt32LE(i * 4));
      }
      this.usersCount = fields[4];
      this.recordsCount = fields[8];
      this.userPacketSize = this.userPacketSize || 28;
    }
    return true;
  }

  async readWithBuffer(command, fct = 0, ext = 0) {
    const MAX_CHUNK = this.tcp ? 0xffc0 : 16 * 1024;
    const commandString = Buffer.alloc(11);
    commandString.writeInt8(1, 0);
    commandString.writeInt16LE(command, 1);
    commandString.writeInt32LE(fct, 3);
    commandString.writeInt32LE(ext, 7);

    const prep = await this._sendCommand(CONST._CMD_PREPARE_BUFFER, commandString, 1024);
    if (!prep.status) {
      throw new Error('Buffered read not supported');
    }
    if (prep.code === CONST.CMD_DATA) {
      return { buffer: prep.data, size: prep.data.length };
    }
    const size = prep.data.readUInt32LE(1);
    const remain = size % MAX_CHUNK;
    const packets = Math.floor((size - remain) / MAX_CHUNK);
    const chunks = [];
    let start = 0;
    for (let i = 0; i < packets; i += 1) {
      const chunk = await this._readChunk(start, MAX_CHUNK);
      chunks.push(chunk);
      start += MAX_CHUNK;
    }
    if (remain) {
      const chunk = await this._readChunk(start, remain);
      chunks.push(chunk);
      start += remain;
    }
    await this._sendCommand(CONST.CMD_FREE_DATA);
    return { buffer: Buffer.concat(chunks), size: start };
  }

  async _readChunk(start, size) {
    const payload = Buffer.alloc(8);
    payload.writeInt32LE(start, 0);
    payload.writeInt32LE(size, 4);
    const respSize = this.tcp ? size + 32 : 1032;
    const res = await this._sendCommand(CONST._CMD_READ_BUFFER, payload, respSize);
    if (!res.status && res.code !== CONST.CMD_DATA) {
      throw new Error(`Cannot read chunk ${start}:${size}`);
    }
    return res.data;
  }

  async getUsers() {
    await this.readSizes();
    if (!this.usersCount) {
      this.nextUid = 1;
      this.nextUserId = '1';
      return [];
    }
    const { buffer, size } = await this.readWithBuffer(CONST.CMD_USERTEMP_RRQ, CONST.FCT_USER);
    if (size <= 4) {
      return [];
    }
    const totalSize = buffer.readUInt32LE(0);
    this.userPacketSize = Math.floor(totalSize / this.usersCount) || 28;
    const data = buffer.slice(4);
    const users = [];
    let maxUid = 0;

    if (this.userPacketSize === 28) {
      for (let offset = 0; offset + 28 <= data.length; offset += 28) {
        const uid = data.readUInt16LE(offset);
        const privilege = data.readUInt8(offset + 2);
        const password = ZK._trimString(data, offset + 3, offset + 8);
        const name = ZK._trimString(data, offset + 8, offset + 16) || `NN-${uid}`;
        const card = data.readUInt32LE(offset + 16);
        const groupId = String(data.readUInt8(offset + 21));
        const userId = String(data.readUInt32LE(offset + 24));
        users.push({ uid, privilege, password, name, card, groupId, userId });
        if (uid > maxUid) maxUid = uid;
      }
    } else {
      for (let offset = 0; offset + 72 <= data.length; offset += 72) {
        const uid = data.readUInt16LE(offset);
        const privilege = data.readUInt8(offset + 2);
        const password = ZK._trimString(data, offset + 3, offset + 11);
        const name = ZK._trimString(data, offset + 11, offset + 35) || `NN-${uid}`;
        const card = data.readUInt32LE(offset + 35);
        const groupId = ZK._trimString(data, offset + 40, offset + 47);
        const userId = ZK._trimString(data, offset + 48, offset + 72);
        users.push({ uid, privilege, password, name, card, groupId, userId });
        if (uid > maxUid) maxUid = uid;
      }
    }

    this.nextUid = maxUid + 1;
    this.nextUserId = String(this.nextUid);
    while (users.find((u) => u.userId === this.nextUserId)) {
      this.nextUid += 1;
      this.nextUserId = String(this.nextUid);
    }
    return users;
  }

  async setUser({ uid, name = '', privilege = CONST.USER_DEFAULT, password = '', groupId = '', userId = '', card = 0 } = {}) {
    const users = await this.getUsers();
    if (!uid) {
      uid = this.nextUid || 1;
    }
    if (!userId) {
      userId = String(uid);
    }
    const priv = [CONST.USER_DEFAULT, CONST.USER_ADMIN].includes(privilege) ? privilege : CONST.USER_DEFAULT;

    let payload;
    if (this.userPacketSize === 28) {
      payload = Buffer.alloc(28);
      payload.writeUInt16LE(uid, 0);
      payload.writeUInt8(priv, 2);
      Buffer.from(password, 'utf8').slice(0, 5).copy(payload, 3);
      Buffer.from(name, 'utf8').slice(0, 8).copy(payload, 8);
      payload.writeUInt32LE(card >>> 0, 16);
      payload.writeUInt8(groupId ? Number(groupId) : 0, 21);
      payload.writeUInt16LE(0, 22); // timezone/reserved
      payload.writeUInt32LE(Number(userId) || 0, 24);
    } else {
      payload = Buffer.alloc(72);
      payload.writeUInt16LE(uid, 0);
      payload.writeUInt8(priv, 2);
      Buffer.from(password, 'utf8').slice(0, 8).copy(payload, 3);
      Buffer.from(name, 'utf8').slice(0, 24).copy(payload, 11);
      payload.writeUInt32LE(card >>> 0, 35);
      Buffer.from(groupId || '', 'utf8').slice(0, 7).copy(payload, 40);
      Buffer.from(userId, 'utf8').slice(0, 24).copy(payload, 48);
    }

    const res = await this._sendCommand(CONST.CMD_USER_WRQ, payload, 1024);
    if (!res.status) {
      throw new Error('Cannot set user');
    }
    await this.refreshData();
    if (uid === this.nextUid) {
      this.nextUid += 1;
      this.nextUserId = String(this.nextUid);
    }
    return true;
  }

  async deleteUser({ uid = 0, userId = '' } = {}) {
    if (!uid && userId) {
      const users = await this.getUsers();
      const found = users.find((u) => u.userId === String(userId));
      if (!found) {
        return false;
      }
      uid = found.uid;
    }
    if (!uid) {
      return false;
    }
    const payload = Buffer.alloc(2);
    payload.writeInt16LE(uid, 0);
    const res = await this._sendCommand(CONST.CMD_DELETE_USER, payload);
    if (!res.status) {
      throw new Error('Cannot delete user');
    }
    await this.refreshData();
    return true;
  }

  async getAttendance() {
    await this.readSizes();
    if (!this.recordsCount) {
      return [];
    }
    const users = await this.getUsers();
    const { buffer, size } = await this.readWithBuffer(CONST.CMD_ATTLOG_RRQ);
    if (size < 4) {
      return [];
    }
    const totalSize = buffer.readUInt32LE(0);
    const recordSize = Math.floor(totalSize / this.recordsCount);
    const data = buffer.slice(4);
    const rows = [];

    if (recordSize === 8) {
      for (let offset = 0; offset + 8 <= data.length; offset += 8) {
        const uid = data.readUInt16LE(offset);
        const status = data.readUInt8(offset + 2);
        const timestamp = decodeTime(data.slice(offset + 3, offset + 7));
        const punch = data.readUInt8(offset + 7);
        const user = users.find((u) => u.uid === uid);
        const userId = user ? user.userId : String(uid);
        rows.push({ uid, userId, status, punch, timestamp });
      }
    } else if (recordSize === 16) {
      for (let offset = 0; offset + 16 <= data.length; offset += 16) {
        const userIdNum = data.readUInt32LE(offset);
        const timestamp = decodeTime(data.slice(offset + 4, offset + 8));
        const status = data.readUInt8(offset + 8);
        const punch = data.readUInt8(offset + 9);
        const userIdStr = String(userIdNum);
        const user = users.find((u) => u.userId === userIdStr || u.uid === userIdNum);
        const uid = user ? user.uid : userIdNum;
        rows.push({ uid, userId: user ? user.userId : userIdStr, status, punch, timestamp });
      }
    } else {
      for (let offset = 0; offset + recordSize <= data.length; offset += recordSize) {
        const uid = data.readUInt16LE(offset);
        const userId = ZK._trimString(data, offset + 2, offset + 26);
        const status = data.readUInt8(offset + 26);
        const timestamp = decodeTime(data.slice(offset + 27, offset + 31));
        const punch = data.readUInt8(offset + 31);
        rows.push({ uid, userId, status, punch, timestamp });
      }
    }
    return rows;
  }

  async refreshData() {
    const res = await this._sendCommand(CONST.CMD_REFRESHDATA);
    if (!res.status) {
      throw new Error('Cannot refresh data');
    }
    return true;
  }

  async _createSocket() {
    if (this.socket) {
      await this._closeSocket();
    }
    if (this.tcp) {
      return this._createTcpSocket();
    }
    return this._createUdpSocket();
  }

  async _closeSocket() {
    return new Promise((resolve) => {
      if (!this.socket) {
        resolve();
        return;
      }
      if (this.tcp) {
        this.socket.removeAllListeners('data');
        this.socket.end(() => {
          this.socket.destroy();
          this.socket = null;
          resolve();
        });
      } else {
        this.socket.close(() => {
          this.socket = null;
          resolve();
        });
      }
    });
  }

  async _createTcpSocket() {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      let settled = false;

      const cleanup = () => {
        socket.removeAllListeners('connect');
        socket.removeAllListeners('error');
        socket.removeAllListeners('timeout');
      };

      socket.setTimeout(this.timeout);

      socket.once('connect', () => {
        settled = true;
        cleanup();
        this.socket = socket;
        resolve(socket);
      });

      socket.once('timeout', () => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        socket.destroy();
        reject(new Error('TCP socket timeout'));
      });

      socket.once('error', (err) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(err);
      });

      socket.connect(this.port, this.ip);
    });
  }

  async _createUdpSocket() {
    return new Promise((resolve, reject) => {
      const socket = dgram.createSocket('udp4');
      let settled = false;

      const cleanup = () => {
        socket.removeAllListeners('listening');
        socket.removeAllListeners('error');
      };

      socket.once('listening', () => {
        settled = true;
        cleanup();
        this.socket = socket;
        resolve(socket);
      });

      socket.once('error', (err) => {
        if (settled) {
          return;
        }
        settled = true;
        cleanup();
        reject(err);
      });

      socket.bind();
    });
  }

  async _sendCommand(command, commandString = Buffer.alloc(0), responseSize = 8) {
    if (command !== CONST.CMD_CONNECT && command !== CONST.CMD_AUTH && !this.isConnected) {
      throw new Error('Not connected');
    }
    const packet = createHeader(command, commandString, this.sessionId, this.replyId);
    const expected = responseSize + (this.tcp ? 8 : 0);
    const raw = this.tcp
      ? await this._sendTcp(packet)
      : await this._sendUdp(packet, expected);

    const header = readHeader(raw.slice(0, 8));
    this.sessionId = header[2];
    this.replyId = header[3];
    const data = raw.slice(8);
    const code = header[0];
    const status = [CONST.CMD_ACK_OK, CONST.CMD_PREPARE_DATA, CONST.CMD_DATA].includes(code);
    return { status, code, header, data };
  }

  async _sendUdp(packet) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('UDP response timeout'));
      }, this.timeout);

      const cleanup = () => {
        clearTimeout(timer);
        this.socket.removeListener('error', onError);
        this.socket.removeListener('message', onMessage);
      };

      const onError = (err) => {
        cleanup();
        reject(err);
      };

      const onMessage = (msg) => {
        cleanup();
        resolve(msg);
      };

      this.socket.once('error', onError);
      this.socket.once('message', onMessage);
      this.socket.send(packet, this.port, this.ip, (err) => {
        if (err) {
          cleanup();
          reject(err);
        }
      });
    });
  }

  async _sendTcp(packet) {
    const top = createTcpTop(packet);
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      let target = null;

      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('TCP response timeout'));
      }, this.timeout);

      const cleanup = () => {
        clearTimeout(timer);
        this.socket.removeListener('data', onData);
        this.socket.removeListener('error', onError);
      };

      const onError = (err) => {
        cleanup();
        reject(err);
      };

      const onData = (chunk) => {
        chunks.push(chunk);
        total += chunk.length;
        const merged = Buffer.concat(chunks);
        if (target === null && merged.length >= 8) {
          target = 8 + merged.readUInt32LE(4);
        }
        if (target !== null && total >= target) {
          cleanup();
          if (!this._validateTcpTop(merged)) {
            reject(new Error('TCP packet invalid'));
            return;
          }
          const size = merged.readUInt32LE(4);
          resolve(merged.slice(8, 8 + size));
        }
      };

      this.socket.once('error', onError);
      this.socket.on('data', onData);

      this.socket.write(top, (err) => {
        if (err) {
          cleanup();
          reject(err);
        }
      });
    });
  }

  _validateTcpTop(packet) {
    if (packet.length < 8) {
      return false;
    }
    const h1 = packet.readUInt16LE(0);
    const h2 = packet.readUInt16LE(2);
    return h1 === CONST.MACHINE_PREPARE_DATA_1 && h2 === CONST.MACHINE_PREPARE_DATA_2;
  }
}

module.exports = ZK;
