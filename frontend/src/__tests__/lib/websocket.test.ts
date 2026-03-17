import { createLiveSocket, type LiveFlowEvent } from "@/lib/websocket";

// ── Mock WebSocket ──────────────────────────────────────────────────

class MockWebSocket {
  static instances: MockWebSocket[] = [];

  // WebSocket readyState constants
  static CONNECTING = 0;
  static OPEN = 1;
  static CLOSING = 2;
  static CLOSED = 3;

  url: string;
  onopen: (() => void) | null = null;
  onmessage: ((msg: { data: string }) => void) | null = null;
  onclose: (() => void) | null = null;
  onerror: (() => void) | null = null;
  readyState: number = 0; // CONNECTING

  constructor(url: string) {
    this.url = url;
    MockWebSocket.instances.push(this);
  }

  close() {
    this.readyState = 3; // CLOSED
    this.onclose?.();
  }

  // Test helper: simulate server message
  simulateMessage(data: unknown) {
    this.onmessage?.({ data: JSON.stringify(data) });
  }

  // Test helper: simulate open
  simulateOpen() {
    this.readyState = 1; // OPEN
    this.onopen?.();
  }

  // Test helper: simulate error
  simulateError() {
    this.onerror?.();
  }
}

// Install mock globally
beforeEach(() => {
  MockWebSocket.instances = [];
  jest.useFakeTimers();
  (global as unknown as Record<string, unknown>).WebSocket = MockWebSocket as unknown as typeof WebSocket;
});

afterEach(() => {
  jest.useRealTimers();
});

// ── Tests ───────────────────────────────────────────────────────────

describe("createLiveSocket", () => {
  it("connects to the correct URL", () => {
    const socket = createLiveSocket({
      onEvent: jest.fn(),
    });
    socket.connect();

    expect(MockWebSocket.instances).toHaveLength(1);
    expect(MockWebSocket.instances[0].url).toContain("/ws/live");
  });

  it("calls onConnect when WebSocket opens", () => {
    const onConnect = jest.fn();
    const socket = createLiveSocket({
      onEvent: jest.fn(),
      onConnect,
    });
    socket.connect();
    MockWebSocket.instances[0].simulateOpen();

    expect(onConnect).toHaveBeenCalledTimes(1);
  });

  it("calls onEvent for real events", () => {
    const onEvent = jest.fn();
    const socket = createLiveSocket({ onEvent });
    socket.connect();
    MockWebSocket.instances[0].simulateOpen();

    const event: LiveFlowEvent = {
      source: "live",
      timestamp: "2026-03-13T10:00:00Z",
      src_ip: "192.168.1.1",
      dst_ip: "10.0.0.1",
      src_port: 12345,
      dst_port: 80,
      protocol: "TCP",
      anomaly_score: -0.5,
      is_anomaly: true,
      predicted_class: "neptune",
      confidence: 0.95,
      is_attack: true,
      features: { duration: 0, src_bytes: 1032 },
    };
    MockWebSocket.instances[0].simulateMessage(event);

    expect(onEvent).toHaveBeenCalledTimes(1);
    expect(onEvent).toHaveBeenCalledWith(expect.objectContaining({
      src_ip: "192.168.1.1",
      is_attack: true,
    }));
  });

  it("filters heartbeat messages", () => {
    const onEvent = jest.fn();
    const socket = createLiveSocket({ onEvent });
    socket.connect();
    MockWebSocket.instances[0].simulateOpen();

    MockWebSocket.instances[0].simulateMessage({ type: "heartbeat" });

    expect(onEvent).not.toHaveBeenCalled();
  });

  it("ignores malformed messages", () => {
    const onEvent = jest.fn();
    const socket = createLiveSocket({ onEvent });
    socket.connect();
    MockWebSocket.instances[0].simulateOpen();

    // Send non-JSON
    MockWebSocket.instances[0].onmessage?.({ data: "not json{{{" });

    expect(onEvent).not.toHaveBeenCalled();
  });

  it("calls onDisconnect when connection closes", () => {
    const onDisconnect = jest.fn();
    const socket = createLiveSocket({
      onEvent: jest.fn(),
      onDisconnect,
    });
    socket.connect();
    MockWebSocket.instances[0].simulateOpen();
    MockWebSocket.instances[0].close();

    expect(onDisconnect).toHaveBeenCalledTimes(1);
  });

  it("reconnects with exponential backoff on unexpected close", () => {
    const socket = createLiveSocket({
      onEvent: jest.fn(),
    });
    socket.connect();
    const ws1 = MockWebSocket.instances[0];
    ws1.simulateOpen();

    // Simulate unexpected close
    ws1.close();
    expect(MockWebSocket.instances).toHaveLength(1);

    // After 1s delay, should reconnect
    jest.advanceTimersByTime(1000);
    expect(MockWebSocket.instances).toHaveLength(2);

    // Close again, should wait 2s
    MockWebSocket.instances[1].close();
    jest.advanceTimersByTime(1500);
    expect(MockWebSocket.instances).toHaveLength(2); // not yet
    jest.advanceTimersByTime(500);
    expect(MockWebSocket.instances).toHaveLength(3);
  });

  it("does not reconnect after intentional disconnect", () => {
    const socket = createLiveSocket({
      onEvent: jest.fn(),
    });
    socket.connect();
    MockWebSocket.instances[0].simulateOpen();

    socket.disconnect();

    jest.advanceTimersByTime(60000);
    // Only the original connection
    expect(MockWebSocket.instances).toHaveLength(1);
  });

  it("reports isConnected correctly", () => {
    const socket = createLiveSocket({
      onEvent: jest.fn(),
    });

    // Before connecting, no WebSocket exists yet
    expect(socket.isConnected()).toBe(false);

    socket.connect();
    // MockWebSocket starts with readyState 0 (CONNECTING)
    expect(MockWebSocket.instances[0].readyState).toBe(0);

    // After open, readyState = 1 (OPEN)
    MockWebSocket.instances[0].simulateOpen();
    expect(socket.isConnected()).toBe(true);

    socket.disconnect();
    expect(socket.isConnected()).toBe(false);
  });

  it("resets backoff delay after successful connection", () => {
    const socket = createLiveSocket({
      onEvent: jest.fn(),
    });
    socket.connect();
    MockWebSocket.instances[0].simulateOpen();

    // Close and wait for reconnect (1s)
    MockWebSocket.instances[0].close();
    jest.advanceTimersByTime(1000);
    expect(MockWebSocket.instances).toHaveLength(2);

    // Open successfully (resets delay)
    MockWebSocket.instances[1].simulateOpen();

    // Close again — should be back to 1s, not 2s
    MockWebSocket.instances[1].close();
    jest.advanceTimersByTime(1000);
    expect(MockWebSocket.instances).toHaveLength(3);
  });
});
