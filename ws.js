const WebSocket = require("ws");

const clients = new Map(); // sessionID -> ws

function initWSS(server) {
  const wss = new WebSocket.Server({ server });

  wss.on("connection", ws => {
    ws.on("message", msg => {
      const data = JSON.parse(msg);

      if (data.type === "bind") {
        clients.set(data.sessionId, ws);
      }
    });

    ws.on("close", () => {
      for (const [sid, socket] of clients) {
        if (socket === ws) clients.delete(sid);
      }
    });
  });
}

function notify(sessionId, payload) {
  const ws = clients.get(sessionId);
  if (ws) {
    ws.send(JSON.stringify(payload));
  }
}



module.exports = { initWSS, notify };
