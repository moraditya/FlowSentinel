const WS_BASE =
  process.env.NEXT_PUBLIC_WS_URL ||
  (typeof window !== "undefined"
    ? `ws://${window.location.hostname}:8000`
    : "ws://localhost:8000");

export interface LiveFlowEvent {
  source: "live" | "replay";
  timestamp: string;
  src_ip: string | null;
  dst_ip: string | null;
  src_port: number | null;
  dst_port: number | null;
  protocol: string | null;
  anomaly_score: number;
  is_anomaly: boolean;
  predicted_class: string | null;
  confidence: number | null;
  is_attack: boolean;
  features: Record<string, number>;
}

interface LiveSocketCallbacks {
  onEvent: (event: LiveFlowEvent) => void;
  onConnect?: () => void;
  onDisconnect?: () => void;
}

export function createLiveSocket(callbacks: LiveSocketCallbacks) {
  let ws: WebSocket | null = null;
  let reconnectDelay = 1000;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let intentionalClose = false;

  function connect() {
    intentionalClose = false;
    ws = new WebSocket(`${WS_BASE}/ws/live`);

    ws.onopen = () => {
      reconnectDelay = 1000;
      callbacks.onConnect?.();
    };

    ws.onmessage = (msg) => {
      try {
        const data = JSON.parse(msg.data);
        // Filter heartbeat messages
        if (data.type === "heartbeat") return;
        callbacks.onEvent(data as LiveFlowEvent);
      } catch {
        // ignore malformed messages
      }
    };

    ws.onclose = () => {
      callbacks.onDisconnect?.();
      if (!intentionalClose) {
        reconnectTimer = setTimeout(() => {
          reconnectDelay = Math.min(reconnectDelay * 2, 30000);
          connect();
        }, reconnectDelay);
      }
    };

    ws.onerror = () => {
      ws?.close();
    };
  }

  function disconnect() {
    intentionalClose = true;
    if (reconnectTimer) clearTimeout(reconnectTimer);
    ws?.close();
    ws = null;
  }

  function isConnected() {
    return ws?.readyState === WebSocket.OPEN;
  }

  return { connect, disconnect, isConnected };
}
