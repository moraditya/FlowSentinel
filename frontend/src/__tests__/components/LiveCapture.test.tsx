import { render, screen, fireEvent, waitFor, act } from "@testing-library/react";
import LiveCapture from "@/components/LiveCapture";
import * as api from "@/lib/api";

jest.mock("@/lib/api", () => ({
  getCaptureStatus: jest.fn(),
  getBaselineStatus: jest.fn(),
  startCapture: jest.fn(),
  stopCapture: jest.fn(),
  collectBaseline: jest.fn(),
  finishBaseline: jest.fn(),
}));

const mockCaptureStatus: api.CaptureStatusResponse = {
  is_capturing: false,
  interface: null,
  packets_captured: 0,
  flows_analyzed: 0,
  threats_detected: 0,
  uptime_seconds: 0,
  error: null,
};

const mockBaselineStatus: api.BaselineStatusResponse = {
  status: "not_collected",
  samples_collected: 0,
  seconds_remaining: 0,
  duration_seconds: 0,
  message: "",
};

beforeEach(() => {
  jest.useFakeTimers();
  (api.getCaptureStatus as jest.Mock).mockResolvedValue(mockCaptureStatus);
  (api.getBaselineStatus as jest.Mock).mockResolvedValue(mockBaselineStatus);
});

afterEach(() => {
  jest.useRealTimers();
  jest.clearAllMocks();
});

describe("LiveCapture", () => {
  it("renders the header title", async () => {
    await act(async () => {
      render(<LiveCapture />);
    });
    expect(screen.getByText("Network Monitor")).toBeInTheDocument();
  });

  it("shows IDLE status initially", async () => {
    await act(async () => {
      render(<LiveCapture />);
    });
    expect(screen.getByText("IDLE")).toBeInTheDocument();
  });

  it("renders interface input", async () => {
    await act(async () => {
      render(<LiveCapture />);
    });
    expect(screen.getByPlaceholderText("Interface")).toBeInTheDocument();
  });

  it("renders baseline duration dropdown", async () => {
    await act(async () => {
      render(<LiveCapture />);
    });
    expect(screen.getByText("60s baseline")).toBeInTheDocument();
  });

  it("renders START CAPTURE button when idle", async () => {
    await act(async () => {
      render(<LiveCapture />);
    });
    expect(screen.getByText("START CAPTURE")).toBeInTheDocument();
  });

  it("calls startCapture and collectBaseline on START", async () => {
    (api.startCapture as jest.Mock).mockResolvedValue({
      ...mockCaptureStatus,
      is_capturing: true,
    });
    (api.collectBaseline as jest.Mock).mockResolvedValue({
      ...mockBaselineStatus,
      status: "collecting",
    });

    await act(async () => {
      render(<LiveCapture />);
    });

    await act(async () => {
      fireEvent.click(screen.getByText("START CAPTURE"));
    });

    expect(api.startCapture).toHaveBeenCalled();
    expect(api.collectBaseline).toHaveBeenCalled();
  });

  it("shows COLLECTING BASELINE status after start", async () => {
    (api.startCapture as jest.Mock).mockResolvedValue({
      ...mockCaptureStatus,
      is_capturing: true,
    });
    (api.collectBaseline as jest.Mock).mockResolvedValue({
      ...mockBaselineStatus,
      status: "collecting",
    });

    await act(async () => {
      render(<LiveCapture />);
    });

    await act(async () => {
      fireEvent.click(screen.getByText("START CAPTURE"));
    });

    expect(screen.getByText("COLLECTING BASELINE")).toBeInTheDocument();
    expect(screen.getByText(/Learning your normal traffic/)).toBeInTheDocument();
  });

  it("shows CANCEL button during baseline", async () => {
    (api.startCapture as jest.Mock).mockResolvedValue({
      ...mockCaptureStatus,
      is_capturing: true,
    });
    (api.collectBaseline as jest.Mock).mockResolvedValue({
      ...mockBaselineStatus,
      status: "collecting",
    });

    await act(async () => {
      render(<LiveCapture />);
    });

    await act(async () => {
      fireEvent.click(screen.getByText("START CAPTURE"));
    });

    expect(screen.getByText("CANCEL")).toBeInTheDocument();
  });

  it("shows error when capture fails", async () => {
    (api.startCapture as jest.Mock).mockResolvedValue({
      ...mockCaptureStatus,
      is_capturing: false,
      error: "Permission denied",
    });

    await act(async () => {
      render(<LiveCapture />);
    });

    await act(async () => {
      fireEvent.click(screen.getByText("START CAPTURE"));
    });

    expect(screen.getByText("Permission denied")).toBeInTheDocument();
  });

  it("calls stopCapture on CANCEL", async () => {
    (api.startCapture as jest.Mock).mockResolvedValue({
      ...mockCaptureStatus,
      is_capturing: true,
    });
    (api.collectBaseline as jest.Mock).mockResolvedValue({
      ...mockBaselineStatus,
      status: "collecting",
    });
    (api.stopCapture as jest.Mock).mockResolvedValue(mockCaptureStatus);

    await act(async () => {
      render(<LiveCapture />);
    });

    await act(async () => {
      fireEvent.click(screen.getByText("START CAPTURE"));
    });

    await act(async () => {
      fireEvent.click(screen.getByText("CANCEL"));
    });

    expect(api.stopCapture).toHaveBeenCalled();
  });

  it("notifies parent of capture state changes", async () => {
    const onCaptureStateChange = jest.fn();
    (api.startCapture as jest.Mock).mockResolvedValue({
      ...mockCaptureStatus,
      is_capturing: true,
    });
    (api.collectBaseline as jest.Mock).mockResolvedValue({
      ...mockBaselineStatus,
      status: "collecting",
    });

    await act(async () => {
      render(<LiveCapture onCaptureStateChange={onCaptureStateChange} />);
    });

    await act(async () => {
      fireEvent.click(screen.getByText("START CAPTURE"));
    });

    expect(onCaptureStateChange).toHaveBeenCalledWith(true, "baseline");
  });

  it("has duration options in dropdown", async () => {
    await act(async () => {
      render(<LiveCapture />);
    });
    expect(screen.getByText("60s baseline")).toBeInTheDocument();
    expect(screen.getByText("2 min baseline")).toBeInTheDocument();
    expect(screen.getByText("5 min baseline")).toBeInTheDocument();
    expect(screen.getByText("10 min baseline")).toBeInTheDocument();
    expect(screen.getByText("30 min baseline")).toBeInTheDocument();
  });

  // ── Rehydration tests (refresh mid-operation) ─────────────────────

  it("rehydrates to baseline phase on mount when backend is collecting", async () => {
    (api.getCaptureStatus as jest.Mock).mockResolvedValue({
      ...mockCaptureStatus,
      is_capturing: true,
    });
    (api.getBaselineStatus as jest.Mock).mockResolvedValue({
      ...mockBaselineStatus,
      status: "collecting",
      seconds_remaining: 30,
      duration_seconds: 60,
    });

    await act(async () => {
      render(<LiveCapture />);
    });

    expect(screen.getByText("COLLECTING BASELINE")).toBeInTheDocument();
  });

  it("rehydrates to monitoring phase on mount when baseline is ready", async () => {
    (api.getCaptureStatus as jest.Mock).mockResolvedValue({
      ...mockCaptureStatus,
      is_capturing: true,
    });
    (api.getBaselineStatus as jest.Mock).mockResolvedValue({
      ...mockBaselineStatus,
      status: "ready",
    });

    await act(async () => {
      render(<LiveCapture />);
    });

    expect(screen.getByText("MONITORING")).toBeInTheDocument();
  });

  it("rehydrates to idle on mount when capture is not running", async () => {
    (api.getCaptureStatus as jest.Mock).mockResolvedValue(mockCaptureStatus);
    (api.getBaselineStatus as jest.Mock).mockResolvedValue(mockBaselineStatus);

    await act(async () => {
      render(<LiveCapture />);
    });

    expect(screen.getByText("IDLE")).toBeInTheDocument();
  });
});
