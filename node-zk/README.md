# pyzk-node (WIP)

Un port inicial de la librería `pyzk` a Node.js para hablar con dispositivos de asistencia ZKTeco por UDP/TCP.

## Estado

- Conexión con handshake y autenticación (`CMD_CONNECT`/`CMD_AUTH`).
- `enableDevice` / `disableDevice`.
- `getTime` / `setTime`.
- `getUsers`, `setUser`, `deleteUser`, `getTemplates`, `getUserTemplate`, `deleteUserTemplate`, `saveUserTemplate`.
- `getAttendance` / `clearAttendance`, `clearData`.
- Info/opts: firmware, serial, platform, MAC, device name, pin width, extend fmt, network params.
- Control: `unlock`, `getLockState`, `writeLcd`/`clearLcd`, `testVoice`, `restart`, `powerOff`.
- Eventos (best-effort): `enrollUser`, `liveCapture`, `regEvent`, `cancelCapture`, `verifyUser`.
- Soporte UDP (por defecto) y TCP (`forceUdp: false`).
- Constantes de protocolo replicadas de `pyzk`.

## Uso rápido

```js
const { ZK } = require('./src');

async function main() {
  const zk = new ZK({ ip: '192.168.1.201', password: 0, verbose: true });
  await zk.connect();
  console.log(await zk.getTime());
  await zk.testVoice(0);
  console.log(await zk.getUsers());
  console.log(await zk.getAttendance());
  await zk.disconnect();
}

main().catch(console.error);
```

Ejecuta `node examples/basic.js` y ajusta la IP/puerto según tu dispositivo.

## Extender

El flujo de cada comando es: construir el paquete (`createHeader`), enviarlo (`_sendCommand`) y parsear `res.data`. El archivo `src/const.js` lista todos los comandos disponibles en `pyzk`; puedes replicar métodos adicionales tomando como referencia `zk/base.py`.

## Licencia

Hereda la licencia GPL-2.0-or-later del proyecto original `pyzk`.
