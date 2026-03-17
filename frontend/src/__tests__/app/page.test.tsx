import { act, fireEvent, render, screen, waitFor } from "@testing-library/react";
import Dashboard from "@/app/page";
import type { LiveFlowEvent } from "@/lib/websocket";
import { getHealth } from "@/lib/api";

jest.mock("@/lib/api", () => ({
  getHealth: jest.fn(),
}));

let latestOnEvent: ((event: LiveFlowEvent) => void) | null = null;

jest.mock("@/lib/websocket", () => ({
  createLiveSocket: jest.fn(({ onEvent }) => {
    latestOnEvent = onEvent;
    return {
      connect: jest.fn(),
      disconnect: jest.fn(),
      isConnected: jest.fn(() => true),
    };
  }),
}));

jest.mock("@/components/Header", () => ({
  __esModule: true,
  default: () => <div>header</div>,
}));

jest.mock("@/components/LiveCapture", () => ({
  __esModule: true,
  default: () => <div>live-capture</div>,
}));

jest.mock("@/components/ReplayPanel", () => ({
  __esModule: true,
  default: ({
    onReplayStateChange,
    onReset,
  }: {
    onReplayStateChange?: (isReplaying: boolean) => void;
    onReset?: () => void;
  }) => (
    <button
      onClick={() => {
        onReplayStateChange?.(false);
        onReset?.();
      }}
    >
      reset replay
    </button>
  ),
}));

jest.mock("@/components/DetectionMetrics", () => ({
  __esModule: true,
  default: () => <div>metrics</div>,
}));

const mockReplayEvent: LiveFlowEvent = {
  source: "replay",
  timestamp: "2026-03-17T12:00:00Z",
  src_ip: "192.168.1.10",
  dst_ip: "10.0.0.1",
  src_port: 45678,
  dst_port: 80,
  protocol: "TCP",
  anomaly_score: -0.42,
  is_anomaly: true,
  predicted_class: "port_scan",
  confidence: 0.91,
  is_attack: true,
  features: { duration: 1.2, src_bytes: 1032 },
};

describe("Dashboard replay reset", () => {
  beforeEach(() => {
    latestOnEvent = null;
    (getHealth as jest.Mock).mockResolvedValue({
      status: "ok",
      model_loaded: false,
      model_type: "none",
      mode: "demo",
    });
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("clears old replay events from the feed when replay is reset", async () => {
    render(<Dashboard />);

    await waitFor(() => {
      expect(getHealth).toHaveBeenCalled();
    });

    expect(latestOnEvent).not.toBeNull();

    await act(async () => {
      latestOnEvent?.(mockReplayEvent);
    });

    expect(screen.getByText("1 flows")).toBeInTheDocument();
    expect(screen.getByText("port_scan")).toBeInTheDocument();

    fireEvent.click(screen.getByText("PCAP REPLAY"));
    fireEvent.click(screen.getByText("reset replay"));

    await waitFor(() => {
      expect(screen.getByText("No live data")).toBeInTheDocument();
    });
    expect(screen.queryByText("1 flows")).not.toBeInTheDocument();
    expect(screen.queryByText("port_scan")).not.toBeInTheDocument();
  });
});
