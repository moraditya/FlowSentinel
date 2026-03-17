import { render, screen } from "@testing-library/react";
import ThreatFeed from "@/components/ThreatFeed";
import type { LiveFlowEvent } from "@/lib/websocket";

const mockAttackEvent: LiveFlowEvent = {
  source: "live",
  timestamp: "2026-03-13T10:30:00Z",
  src_ip: "192.168.1.100",
  dst_ip: "10.0.0.1",
  src_port: 45678,
  dst_port: 80,
  protocol: "TCP",
  anomaly_score: -0.342,
  is_anomaly: true,
  predicted_class: "neptune",
  confidence: 0.97,
  is_attack: true,
  features: { duration: 0, src_bytes: 1032 },
};

const mockSafeEvent: LiveFlowEvent = {
  source: "live",
  timestamp: "2026-03-13T10:31:00Z",
  src_ip: "192.168.1.50",
  dst_ip: "10.0.0.2",
  src_port: 54321,
  dst_port: 443,
  protocol: "TCP",
  anomaly_score: 0.5,
  is_anomaly: false,
  predicted_class: null,
  confidence: null,
  is_attack: false,
  features: { duration: 5, src_bytes: 256 },
};

const mockAnomalyEvent: LiveFlowEvent = {
  source: "live",
  timestamp: "2026-03-13T10:32:00Z",
  src_ip: "10.0.0.5",
  dst_ip: "10.0.0.1",
  src_port: 9999,
  dst_port: 22,
  protocol: "TCP",
  anomaly_score: -0.1,
  is_anomaly: true,
  predicted_class: "normal",
  confidence: 0.6,
  is_attack: false,
  features: { duration: 1 },
};

describe("ThreatFeed", () => {
  it("renders the header title", () => {
    render(<ThreatFeed events={[]} />);
    expect(screen.getByText("Live Traffic")).toBeInTheDocument();
  });

  describe("idle state (no capture)", () => {
    it("shows start capture message", () => {
      render(<ThreatFeed events={[]} phase="idle" />);
      expect(screen.getByText("No live data")).toBeInTheDocument();
      expect(screen.getByText(/Start capture/)).toBeInTheDocument();
    });
  });

  describe("baseline phase", () => {
    it("shows capturing baseline message when empty", () => {
      render(<ThreatFeed events={[]} phase="baseline" isLiveMode />);
      expect(screen.getByText(/Capturing baseline/)).toBeInTheDocument();
    });

    it("shows LEARNING badge", () => {
      render(<ThreatFeed events={[]} phase="baseline" isLiveMode />);
      expect(screen.getByText("LEARNING")).toBeInTheDocument();
    });

    it("labels flows as LEARNING during baseline", () => {
      render(<ThreatFeed events={[mockSafeEvent]} phase="baseline" isLiveMode />);
      const badges = screen.getAllByText("LEARNING");
      expect(badges.length).toBeGreaterThanOrEqual(1);
    });

    it("shows dash instead of class name during baseline", () => {
      render(<ThreatFeed events={[mockAttackEvent]} phase="baseline" isLiveMode />);
      expect(screen.queryByText("neptune")).not.toBeInTheDocument();
    });
  });

  describe("monitoring phase", () => {
    it("shows CLASSIFYING badge", () => {
      render(<ThreatFeed events={[]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("CLASSIFYING")).toBeInTheDocument();
    });

    it("shows waiting message when empty", () => {
      render(<ThreatFeed events={[]} phase="monitoring" isLiveMode />);
      expect(screen.getByText(/waiting for flows/)).toBeInTheDocument();
    });

    it("renders flow count", () => {
      render(<ThreatFeed events={[mockAttackEvent, mockSafeEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("2 flows")).toBeInTheDocument();
    });
  });

  describe("attack events", () => {
    it("renders THREAT badge for attack events", () => {
      render(<ThreatFeed events={[mockAttackEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("THREAT")).toBeInTheDocument();
    });

    it("renders predicted class name", () => {
      render(<ThreatFeed events={[mockAttackEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("neptune")).toBeInTheDocument();
    });

    it("shows anomaly score for anomalous events", () => {
      render(<ThreatFeed events={[mockAttackEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("-0.342")).toBeInTheDocument();
    });

    it("shows source and dest with ports", () => {
      render(<ThreatFeed events={[mockAttackEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText(/192\.168\.1\.100:45678.*10\.0\.0\.1:80/)).toBeInTheDocument();
    });

    it("shows protocol", () => {
      render(<ThreatFeed events={[mockAttackEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("TCP")).toBeInTheDocument();
    });
  });

  describe("safe events", () => {
    it("renders SAFE badge", () => {
      render(<ThreatFeed events={[mockSafeEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("SAFE")).toBeInTheDocument();
    });

    it("shows normal for null predicted_class", () => {
      render(<ThreatFeed events={[mockSafeEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("normal")).toBeInTheDocument();
    });

    it("does not show anomaly score for non-anomalous events", () => {
      render(<ThreatFeed events={[mockSafeEvent]} phase="monitoring" isLiveMode />);
      expect(screen.queryByText("0.500")).not.toBeInTheDocument();
    });
  });

  describe("anomaly events (not attack)", () => {
    it("renders ANOMALY badge", () => {
      render(<ThreatFeed events={[mockAnomalyEvent]} phase="monitoring" isLiveMode />);
      expect(screen.getByText("ANOMALY")).toBeInTheDocument();
    });
  });

  describe("mixed events", () => {
    it("renders correct badges for mixed events", () => {
      render(
        <ThreatFeed
          events={[mockAttackEvent, mockSafeEvent, mockAnomalyEvent]}
          phase="monitoring"
          isLiveMode
        />
      );
      expect(screen.getByText("THREAT")).toBeInTheDocument();
      expect(screen.getByText("SAFE")).toBeInTheDocument();
      expect(screen.getByText("ANOMALY")).toBeInTheDocument();
      expect(screen.getByText("3 flows")).toBeInTheDocument();
    });
  });
});
