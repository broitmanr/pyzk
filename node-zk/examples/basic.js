const { ZK } = require('../src');

async function main() {
  // Update the IP/password with your device credentials.
  const zk = new ZK({ ip: '192.168.1.201', password: 0, verbose: true });
  try {
    await zk.connect();
    console.log('Connected');

    const time = await zk.getTime();
    console.log('Device time:', time.toISOString());

    const played = await zk.testVoice(0);
    console.log('Test voice:', played ? 'ok' : 'failed');

    const users = await zk.getUsers();
    console.log('Users:', users);

    const att = await zk.getAttendance();
    console.log('Attendance count:', att.length);

    await zk.disconnect();
  } catch (err) {
    console.error('Error:', err.message);
    await zk.disconnect();
  }
}

main();
