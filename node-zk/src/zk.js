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
    this.isEnabled = true;

    this.usersCount = 0;
    this.recordsCount = 0;
    this.userPacketSize = 28; // default zk6
    this.nextUid = 1;
    this.nextUserId = '1';
    this.fingers = 0;
    this.cards = 0;
    this.fingersCap = 0;
    this.usersCap = 0;
    this.recCap = 0;
    this.fingersAv = 0;
    this.usersAv = 0;
    this.recAv = 0;
    this.faces = 0;
    this.facesCap = 0;
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
    this.isEnabled = true;
    return true;
  }

  async disableDevice() {
    const res = await this._sendCommand(CONST.CMD_DISABLEDEVICE);
    if (!res.status) {
      throw new Error('Cannot disable device');
    }
    this.isEnabled = false;
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

  async getFirmwareVersion() {
    const res = await this._sendCommand(CONST.CMD_GET_VERSION, Buffer.alloc(0), 1024);
    if (!res.status) {
      throw new Error('Cannot get firmware version');
    }
    return res.data.toString().split('\x00')[0];
  }

  async getSerialNumber() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('~SerialNumber\x00'), 1024);
    if (!res.status) {
      throw new Error('Cannot get serial number');
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw.split('\x00')[0].replace('=', '');
  }

  async getPlatform() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('~Platform\x00'), 1024);
    if (!res.status) {
      throw new Error('Cannot get platform');
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw.split('\x00')[0].replace('=', '');
  }

  async getMac() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('MAC\x00'), 1024);
    if (!res.status) {
      throw new Error('Cannot get MAC address');
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw.split('\x00')[0];
  }

  async getDeviceName() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('~DeviceName\x00'), 1024);
    if (!res.status) {
      return '';
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw.split('\x00')[0];
  }

  async getFaceVersion() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('ZKFaceVersion\x00'), 1024);
    if (!res.status) {
      return null;
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw ? Number(raw.split('\x00')[0]) || 0 : 0;
  }

  async getFpVersion() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('~ZKFPVersion\x00'), 1024);
    if (!res.status) {
      throw new Error('Cannot get fingerprint version');
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw ? Number(raw.replace(/=/g, '').split('\x00')[0]) || 0 : 0;
  }

  async getExtendFmt() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('~ExtendFmt\x00'), 1024);
    if (!res.status) {
      return null;
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw ? Number(raw.split('\x00')[0]) || 0 : 0;
  }

  async getUserExtendFmt() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('~UserExtFmt\x00'), 1024);
    if (!res.status) {
      return null;
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw ? Number(raw.split('\x00')[0]) || 0 : 0;
  }

  async getFaceFunOn() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('FaceFunOn\x00'), 1024);
    if (!res.status) {
      return null;
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw ? Number(raw.split('\x00')[0]) || 0 : 0;
  }

  async getCompatOldFirmware() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('CompatOldFirmware\x00'), 1024);
    if (!res.status) {
      return null;
    }
    const raw = res.data.toString().split('=', 2)[1] || '';
    return raw ? Number(raw.split('\x00')[0]) || 0 : 0;
  }

  async getNetworkParams() {
    const ip = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('IPAddress\x00'), 1024);
    const mask = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('NetMask\x00'), 1024);
    const gate = await this._sendCommand(CONST.CMD_OPTIONS_RRQ, Buffer.from('GATEIPAddress\x00'), 1024);
    return {
      ip: ip.status ? (ip.data.toString().split('=', 2)[1] || '').split('\x00')[0] : this.ip,
      mask: mask.status ? (mask.data.toString().split('=', 2)[1] || '').split('\x00')[0] : '',
      gateway: gate.status ? (gate.data.toString().split('=', 2)[1] || '').split('\x00')[0] : ''
    };
  }

  async getPinWidth() {
    const payload = Buffer.from(' P');
    const res = await this._sendCommand(CONST.CMD_GET_PINWIDTH, payload, 9);
    if (!res.status) {
      throw new Error('Cannot get pin width');
    }
    return res.data[0];
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
      this.fingers = fields[6];
      this.recordsCount = fields[8];
      this.cards = fields[12];
      this.fingersCap = fields[14];
      this.usersCap = fields[15];
      this.recCap = fields[16];
      this.fingersAv = fields[17];
      this.usersAv = fields[18];
      this.recAv = fields[19];
      this.userPacketSize = this.userPacketSize || 28;
      if (data.length >= 92) {
        const faceFields = [];
        for (let j = 0; j < 3; j += 1) {
          faceFields.push(data.readInt32LE(80 + j * 4));
        }
        this.faces = faceFields[0];
        this.facesCap = faceFields[2];
      }
    }
    return true;
  }

  async freeData() {
    const res = await this._sendCommand(CONST.CMD_FREE_DATA);
    if (!res.status) {
      throw new Error('Cannot free data');
    }
    return true;
  }

  async unlock(time = 3) {
    const payload = Buffer.alloc(4);
    payload.writeUInt32LE(Math.trunc(time) * 10, 0);
    const res = await this._sendCommand(CONST.CMD_UNLOCK, payload);
    if (!res.status) {
      throw new Error('Cannot unlock door');
    }
    return true;
  }

  async getLockState() {
    const res = await this._sendCommand(CONST.CMD_DOORSTATE_RRQ);
    return Boolean(res.status);
  }

  async writeLcd(lineNumber, text) {
    const payload = Buffer.alloc(3 + Buffer.byteLength(text, 'utf8'));
    payload.writeInt16LE(lineNumber, 0);
    payload.writeInt8(0, 2);
    payload.write(' ' + text, 3);
    const res = await this._sendCommand(CONST.CMD_WRITE_LCD, payload);
    if (!res.status) {
      throw new Error('Cannot write LCD');
    }
    return true;
  }

  async clearLcd() {
    const res = await this._sendCommand(CONST.CMD_CLEAR_LCD);
    if (!res.status) {
      throw new Error('Cannot clear LCD');
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

  _fingerRepackOnly(finger) {
    const template = Buffer.isBuffer(finger.template) ? finger.template : Buffer.from(finger.template || []);
    const buf = Buffer.alloc(2 + template.length);
    buf.writeUInt16LE(template.length, 0);
    template.copy(buf, 2);
    return buf;
  }

  _userRepack29(user) {
    const buf = Buffer.alloc(29);
    buf.writeUInt8(2, 0);
    buf.writeUInt16LE(user.uid, 1);
    buf.writeUInt8(user.privilege, 3);
    Buffer.from(user.password || '', 'utf8').slice(0, 5).copy(buf, 4);
    Buffer.from(user.name || '', 'utf8').slice(0, 8).copy(buf, 9);
    buf.writeUInt32LE(user.card >>> 0, 17);
    // offset 21 is padding (x)
    buf.writeUInt8(user.groupId ? Number(user.groupId) : 0, 22);
    buf.writeInt16LE(0, 23); // timezone/reserved (h)
    buf.writeUInt32LE(Number(user.userId) || 0, 25);
    return buf;
  }

  _userRepack73(user) {
    const buf = Buffer.alloc(73);
    buf.writeUInt8(2, 0);
    buf.writeUInt16LE(user.uid, 1);
    buf.writeUInt8(user.privilege, 3);
    Buffer.from(user.password || '', 'utf8').slice(0, 8).copy(buf, 4);  // 8s
    Buffer.from(user.name || '', 'utf8').slice(0, 24).copy(buf, 12);     // 24s
    buf.writeUInt32LE(user.card >>> 0, 36);                               // I
    buf.writeUInt8(1, 40);                                                // B (constant 1)
    Buffer.from(user.groupId || '', 'utf8').slice(0, 7).copy(buf, 41);    // 7s
    // offset 48 is padding (x)
    Buffer.from(user.userId || '', 'utf8').slice(0, 24).copy(buf, 49);    // 24s
    return buf;
  }

  async _sendWithBuffer(buffer) {
    const MAX_CHUNK = 1024;
    await this.freeData();
    const prep = Buffer.alloc(4);
    prep.writeUInt32LE(buffer.length, 0);
    const ok = await this._sendCommand(CONST.CMD_PREPARE_DATA, prep);
    if (!ok.status) {
      throw new Error('Cannot prepare data');
    }
    let start = 0;
    while (start + MAX_CHUNK <= buffer.length) {
      await this._sendChunk(buffer.slice(start, start + MAX_CHUNK));
      start += MAX_CHUNK;
    }
    if (start < buffer.length) {
      await this._sendChunk(buffer.slice(start));
    }
  }

  async _sendChunk(chunk) {
    const res = await this._sendCommand(CONST.CMD_DATA, chunk);
    if (!res.status) {
      throw new Error('Cannot send chunk');
    }
    return true;
  }

  async saveUserTemplate(user, fingers = []) {
    if (!user) {
      throw new Error('User is required');
    }
    const targetUser = user.uid ? user : (await this.getUsers()).find((u) => u.uid === user || u.userId === String(user));
    if (!targetUser) {
      throw new Error('Cannot find user');
    }
    const fingerList = Array.isArray(fingers) ? fingers : [fingers];
    return this.HRSaveUserTemplates([[targetUser, fingerList]]);
  }

  async HRSaveUserTemplates(userTemplates) {
    let upack = Buffer.alloc(0);
    let fpack = Buffer.alloc(0);
    let table = Buffer.alloc(0);
    let tstart = 0;
    const fnum = 0x10;
    for (const [user, fingers] of userTemplates) {
      const u = user;
      if (this.userPacketSize === 28) {
        upack = Buffer.concat([upack, this._userRepack29(u)]);
      } else {
        upack = Buffer.concat([upack, this._userRepack73(u)]);
      }
      for (const finger of fingers) {
        const tfp = this._fingerRepackOnly(finger);
        const entry = Buffer.alloc(8);
        entry.writeInt8(2, 0);
        entry.writeUInt16LE(u.uid, 1);
        entry.writeInt8(fnum + finger.fid, 3);
        entry.writeUInt32LE(tstart, 4);
        table = Buffer.concat([table, entry]);
        tstart += tfp.length;
        fpack = Buffer.concat([fpack, tfp]);
      }
    }
    const head = Buffer.alloc(12);
    head.writeUInt32LE(upack.length, 0);
    head.writeUInt32LE(table.length, 4);
    head.writeUInt32LE(fpack.length, 8);
    const packet = Buffer.concat([head, upack, table, fpack]);
    await this._sendWithBuffer(packet);
    const payload = Buffer.alloc(8);
    payload.writeUInt32LE(12, 0);
    payload.writeUInt16LE(0, 4);
    payload.writeUInt16LE(8, 6);
    const res = await this._sendCommand(CONST._CMD_SAVE_USERTEMPS, payload);
    if (!res.status) {
      throw new Error('Cannot save user templates');
    }
    await this.refreshData();
  }

  async deleteUserTemplate({ uid = 0, tempId = 0, userId = '' } = {}) {
    if (this.tcp && userId) {
      const payload = Buffer.alloc(25);
      Buffer.from(String(userId)).slice(0, 24).copy(payload, 0);
      payload.writeUInt8(tempId, 24);
      const res = await this._sendCommand(CONST._CMD_DEL_USER_TEMP, payload);
      return Boolean(res.status);
    }
    if (!uid && userId) {
      const users = await this.getUsers();
      const found = users.find((u) => u.userId === String(userId));
      if (!found) return false;
      uid = found.uid;
    }
    if (!uid) return false;
    const payload = Buffer.alloc(3);
    payload.writeInt16LE(uid, 0);
    payload.writeInt8(tempId, 2);
    const res = await this._sendCommand(CONST.CMD_DELETE_USERTEMP, payload);
    return Boolean(res.status);
  }

  async getUserTemplate({ uid = 0, tempId = 0, userId = '' } = {}) {
    if (!uid && userId) {
      const users = await this.getUsers();
      const found = users.find((u) => u.userId === String(userId));
      if (!found) return null;
      uid = found.uid;
    }
    const payload = Buffer.alloc(3);
    payload.writeInt16LE(uid, 0);
    payload.writeInt8(tempId, 2);
    for (let attempt = 0; attempt < 3; attempt += 1) {
      const res = await this._sendCommand(CONST._CMD_GET_USERTEMP, payload, 1032);
      const data = await this._receiveChunk(res);
      if (data) {
        let tpl = data.slice(0, -1);
        if (tpl.length >= 6 && tpl.slice(-6).equals(Buffer.alloc(6))) {
          tpl = tpl.slice(0, -6);
        }
        return { uid, fid: tempId, valid: 1, template: tpl };
      }
    }
    return null;
  }

  async getTemplates() {
    await this.readSizes();
    if (!this.fingers) {
      return [];
    }
    const { buffer, size } = await this.readWithBuffer(CONST.CMD_DB_RRQ, CONST.FCT_FINGERTMP);
    if (size < 4) {
      return [];
    }
    let total = buffer.readInt32LE(0);
    let data = buffer.slice(4);
    const templates = [];
    while (total > 0 && data.length >= 6) {
      const sizeRec = data.readUInt16LE(0);
      const uid = data.readUInt16LE(2);
      const fid = data.readInt8(4);
      const valid = data.readInt8(5);
      const tpl = data.slice(6, sizeRec);
      templates.push({ uid, fid, valid, template: tpl });
      data = data.slice(sizeRec);
      total -= sizeRec;
    }
    return templates;
  }

  async cancelCapture() {
    const res = await this._sendCommand(CONST.CMD_CANCELCAPTURE);
    return Boolean(res.status);
  }

  async verifyUser() {
    const res = await this._sendCommand(CONST.CMD_STARTVERIFY);
    if (!res.status) {
      throw new Error('Cannot verify');
    }
    return true;
  }

  async regEvent(flags) {
    const payload = Buffer.alloc(4);
    payload.writeUInt32LE(flags >>> 0, 0);
    const res = await this._sendCommand(CONST.CMD_REG_EVENT, payload);
    if (!res.status) {
      throw new Error(`Cannot register events ${flags}`);
    }
    return true;
  }

  async setSdkBuild1() {
    const res = await this._sendCommand(CONST.CMD_OPTIONS_WRQ, Buffer.from('SDKBuild=1'));
    return Boolean(res.status);
  }

  async enrollUser({ uid = 0, tempId = 0, userId = '' } = {}) {
    if (!userId) {
      const users = await this.getUsers();
      const found = users.find((u) => u.uid === uid);
      if (!found) return false;
      userId = found.userId;
    }
    const payload = this.tcp
      ? (() => {
          const buf = Buffer.alloc(26);
          Buffer.from(String(userId)).slice(0, 24).copy(buf, 0);
          buf.writeInt8(tempId, 24);
          buf.writeInt8(1, 25);
          return buf;
        })()
      : (() => {
          const buf = Buffer.alloc(5);
          buf.writeUInt32LE(Number(userId) || 0, 0);
          buf.writeInt8(tempId, 4);
          return buf;
        })();

    await this.cancelCapture();
    const res = await this._sendCommand(CONST.CMD_STARTENROLL, payload);
    if (!res.status) {
      throw new Error(`Cannot enroll user #${uid} [${tempId}]`);
    }
    // Best-effort waiting for events (mirrors Python flow)
    const attempts = 3;
    let success = false;
    this.tcp ? this.socket.setTimeout(60000) : null;
    for (let i = 0; i < attempts; i += 1) {
      const ev1 = this.tcp ? await this._recvTcpRaw() : await this._recvUdpOnce();
      await this._ackOk().catch(() => {});
      const ev2 = this.tcp ? await this._recvTcpRaw() : await this._recvUdpOnce();
      await this._ackOk().catch(() => {});
      const resCode = this._extractEnrollCode(ev2);
      if (resCode === 0x64) {
        continue;
      }
      if (resCode === 0) {
        success = true;
      }
      break;
    }
    this.tcp ? this.socket.setTimeout(this.timeout) : null;
    await this.regEvent(0);
    await this.cancelCapture();
    await this.verifyUser();
    return success;
  }

  _extractEnrollCode(buffer) {
    if (!buffer) return null;
    if (this.tcp) {
      if (!this._validateTcpTop(buffer)) return null;
      if (buffer.length < 18) return null;
      return buffer.readUInt16LE(16);
    }
    if (buffer.length < 10) return null;
    return buffer.readUInt16LE(8);
  }

  async *liveCapture(newTimeout = 10000) {
    const wasEnabled = this.isEnabled;
    const users = await this.getUsers();
    await this.cancelCapture();
    await this.verifyUser();
    if (!this.isEnabled) {
      await this.enableDevice();
    }
    await this.regEvent(CONST.EF_ATTLOG);
    const prevTimeout = this.timeout;
    this.timeout = newTimeout;
    let running = true;
    const stop = () => {
      running = false;
    };
    this.end_live_capture = stop;
    while (running) {
      try {
        const pkt = this.tcp ? await this._recvTcpRaw() : await this._recvUdpOnce();
        await this._ackOk().catch(() => {});
        const offset = this.tcp ? 8 : 0;
        const header = readHeader(pkt.slice(offset, offset + 8));
        if (header[0] !== CONST.CMD_REG_EVENT) {
          continue;
        }
        let data = pkt.slice(offset + 8);
        while (data.length >= 10) {
          let userId;
          let status;
          let punch;
          let timehex;
          if (data.length >= 10 && data.length < 12) {
            [userId, status, punch] = [data.readUInt16LE(0), data.readUInt8(2), data.readUInt8(3)];
            timehex = data.slice(4, 10);
            data = data.slice(10);
          } else if (data.length >= 12 && data.length < 14) {
            [userId, status, punch] = [data.readUInt32LE(0), data.readUInt8(4), data.readUInt8(5)];
            timehex = data.slice(6, 12);
            data = data.slice(12);
          } else {
            userId = ZK._trimString(data, 0, 24);
            status = data.readUInt8(24);
            punch = data.readUInt8(25);
            timehex = data.slice(26, 32);
            data = data.slice(Math.min(52, data.length));
          }
          const ts = this._decodeTimeHex(timehex);
          const found = users.find((u) => u.userId === String(userId));
          const uid = found ? found.uid : Number(userId) || 0;
          yield { userId: String(userId), uid, status, punch, timestamp: ts };
        }
      } catch (err) {
        if (this.verbose) this.log(`live_capture error/timeout: ${err.message}`);
        yield null;
      }
    }
    this.timeout = prevTimeout;
    await this.regEvent(0);
    if (!wasEnabled) {
      await this.disableDevice();
    }
  }

  _decodeTimeHex(buf) {
    if (!buf || buf.length < 6) return new Date();
    const year = buf.readUInt8(0) + 2000;
    const month = buf.readUInt8(1);
    const day = buf.readUInt8(2);
    const hour = buf.readUInt8(3);
    const minute = buf.readUInt8(4);
    const second = buf.readUInt8(5);
    return new Date(year, month - 1, day, hour, minute, second);
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

  async clearAttendance() {
    const res = await this._sendCommand(CONST.CMD_CLEAR_ATTLOG);
    if (!res.status) {
      throw new Error('Cannot clear attendance');
    }
    return true;
  }

  async clearData() {
    const res = await this._sendCommand(CONST.CMD_CLEAR_DATA);
    if (!res.status) {
      throw new Error('Cannot clear data');
    }
    this.nextUid = 1;
    return true;
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
    const raw = this.tcp
      ? await this._sendTcp(packet)
      : await this._sendUdp(packet);

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

  async _ackOk() {
    const header = createHeader(CONST.CMD_ACK_OK, Buffer.alloc(0), this.sessionId, CONST.USHRT_MAX - 1);
    if (this.tcp) {
      const top = createTcpTop(header);
      return new Promise((resolve, reject) => {
        this.socket.write(top, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
    }
    return new Promise((resolve, reject) => {
      this.socket.send(header, this.port, this.ip, (err) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  async _recvUdpOnce() {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('UDP receive timeout'));
      }, this.timeout);
      const cleanup = () => {
        clearTimeout(timer);
        this.socket.removeListener('message', onMsg);
        this.socket.removeListener('error', onErr);
      };
      const onErr = (err) => {
        cleanup();
        reject(err);
      };
      const onMsg = (msg) => {
        cleanup();
        resolve(msg);
      };
      this.socket.once('error', onErr);
      this.socket.once('message', onMsg);
    });
  }

  async _recvTcpRaw() {
    return new Promise((resolve, reject) => {
      const chunks = [];
      let total = 0;
      let target = null;
      const timer = setTimeout(() => {
        cleanup();
        reject(new Error('TCP receive timeout'));
      }, this.timeout);
      const cleanup = () => {
        clearTimeout(timer);
        this.socket.removeListener('data', onData);
        this.socket.removeListener('error', onErr);
      };
      const onErr = (err) => {
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
          resolve(Buffer.concat(chunks));
        }
      };
      this.socket.once('error', onErr);
      this.socket.on('data', onData);
    });
  }

  async _receiveChunk(initialResponse) {
    if (initialResponse.code === CONST.CMD_DATA) {
      return initialResponse.data;
    }
    if (initialResponse.code !== CONST.CMD_PREPARE_DATA) {
      return null;
    }
    const size = initialResponse.data.readUInt32LE(0);
    const chunks = [];
    let remaining = size;
    while (remaining > 0) {
      const packet = this.tcp ? await this._recvTcpRaw() : await this._recvUdpOnce();
      const offset = this.tcp ? 8 : 0;
      const header = readHeader(packet.slice(offset, offset + 8));
      const body = packet.slice(offset + 8);
      if (header[0] === CONST.CMD_DATA) {
        chunks.push(body);
        remaining -= body.length;
      } else if (header[0] === CONST.CMD_ACK_OK) {
        break;
      } else {
        break;
      }
    }
    return Buffer.concat(chunks).slice(0, size);
  }
}

module.exports = ZK;
