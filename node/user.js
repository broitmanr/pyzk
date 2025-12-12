'use strict';

class User {
  constructor(uid, name, privilege, password = '', groupId = '', userId = '', card = 0, encoding = 'UTF-8') {
    this.uid = uid;
    this.name = `${name}`;
    this.privilege = privilege;
    this.password = `${password}`;
    this.groupId = `${groupId}`;
    this.userId = `${userId}`;
    this.card = Number(card);
    this.encoding = encoding;
  }

  static jsonUnpack(json) {
    return new User(
      json.uid,
      json.name,
      json.privilege,
      json.password,
      json.group_id,
      json.user_id,
      json.card
    );
  }

  repack29() {
    const buffer = Buffer.alloc(29);
    const userId = Number.parseInt(this.userId || '0', 10);
    const group = this.groupId ? Number.parseInt(this.groupId, 10) : 0;
    let offset = 0;
    buffer.writeUInt8(2, offset); offset += 1;
    buffer.writeUInt16LE(this.uid, offset); offset += 2;
    buffer.writeUInt8(this.privilege, offset); offset += 1;
    buffer.write(this.password, offset, 5, this.encoding); offset += 5;
    buffer.write(this.name, offset, 8, this.encoding); offset += 8;
    buffer.writeUInt32LE(this.card >>> 0, offset); offset += 4;
    buffer.writeUInt16LE(Number.isNaN(group) ? 0 : group, offset); offset += 2;
    buffer.writeUInt8(0, offset); offset += 1;
    buffer.writeUInt32LE(Number.isNaN(userId) ? 0 : userId, offset);
    return buffer;
  }

  repack73() {
    const buffer = Buffer.alloc(73);
    const group = this.groupId || '';
    let offset = 0;
    buffer.writeUInt8(2, offset); offset += 1;
    buffer.writeUInt16LE(this.uid, offset); offset += 2;
    buffer.writeUInt8(this.privilege, offset); offset += 1;
    buffer.write(this.password, offset, 8, this.encoding); offset += 8;
    buffer.write(this.name, offset, 24, this.encoding); offset += 24;
    buffer.writeUInt32LE(this.card >>> 0, offset); offset += 4;
    buffer.writeUInt8(1, offset); offset += 1;
    buffer.write(group, offset, 7, this.encoding); offset += 7;
    buffer.writeUInt8(0, offset); offset += 1;
    buffer.write(this.userId, offset, 24, this.encoding);
    return buffer;
  }

  isDisabled() {
    return Boolean(this.privilege & 1);
  }

  isEnabled() {
    return !this.isDisabled();
  }

  usertype() {
    return this.privilege & 0xE;
  }

  toString() {
    return `<User>: [uid:${this.uid}, name:${this.name} user_id:${this.userId}]`;
  }
}

module.exports = User;
