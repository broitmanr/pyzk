'use strict';

const { ZK, consts } = require('../zk');

const zk = new ZK('192.168.2.201', 4370);

async function main() {
  let conn;
  try {
    conn = await zk.connect();
    console.log('Disabling device ...');
    await conn.disable_device();
    console.log('--- Get User ---');
    const users = await conn.getUsers();
    for (const user of users) {
      const privilege = user.privilege === consts.USER_ADMIN ? 'Admin' : 'User';
      console.log(`+ UID #${user.uid}`);
      console.log(`  Name       : ${user.name}`);
      console.log(`  Privilege  : ${privilege}`);
      console.log(`  Password   : ${user.password}`);
      console.log(`  Group ID   : ${user.groupId}`);
      console.log(`  User  ID   : ${user.userId}`);
    }
    console.log('Enabling device ...');
    await conn.enable_device();
  } catch (err) {
    console.error(`Process terminate : ${err.message}`);
  } finally {
    if (conn) {
      await conn.disconnect();
    }
  }
}

main();
