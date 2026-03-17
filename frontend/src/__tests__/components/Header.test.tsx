import { render, screen } from "@testing-library/react";
import Header from "@/components/Header";

// Mock lucide-react icons so they render as simple elements
jest.mock("lucide-react", () => ({
  Shield: (props: Record<string, unknown>) => <svg data-testid="shield-icon" {...props} />,
  Wifi: (props: Record<string, unknown>) => <svg data-testid="wifi-icon" {...props} />,
  WifiOff: (props: Record<string, unknown>) => <svg data-testid="wifioff-icon" {...props} />,
}));

describe("Header", () => {
  it("renders the NIDS title", () => {
    render(<Header isOnline={true} />);
    expect(screen.getByText("NIDS")).toBeInTheDocument();
  });

  it("renders the subtitle", () => {
    render(<Header isOnline={true} />);
    expect(
      screen.getByText("Network Intrusion Detection System")
    ).toBeInTheDocument();
  });

  it("renders version badge", () => {
    render(<Header isOnline={true} />);
    expect(screen.getByText("v2.0")).toBeInTheDocument();
  });

  it("renders the decorative center text", () => {
    render(<Header isOnline={false} />);
    expect(
      screen.getByText("Threat Intelligence Dashboard")
    ).toBeInTheDocument();
  });

  describe("when isOnline is true", () => {
    beforeEach(() => {
      render(<Header isOnline={true} />);
    });

    it("displays SYSTEM ONLINE status text", () => {
      expect(screen.getByText("SYSTEM ONLINE")).toBeInTheDocument();
    });

    it("renders the Wifi icon", () => {
      expect(screen.getByTestId("wifi-icon")).toBeInTheDocument();
    });

    it("does not render the WifiOff icon", () => {
      expect(screen.queryByTestId("wifioff-icon")).not.toBeInTheDocument();
    });

    it("renders the shield icon", () => {
      expect(screen.getByTestId("shield-icon")).toBeInTheDocument();
    });
  });

  describe("when isOnline is false", () => {
    beforeEach(() => {
      render(<Header isOnline={false} />);
    });

    it("displays OFFLINE status text", () => {
      expect(screen.getByText("OFFLINE")).toBeInTheDocument();
    });

    it("does not display SYSTEM ONLINE", () => {
      expect(screen.queryByText("SYSTEM ONLINE")).not.toBeInTheDocument();
    });

    it("renders the WifiOff icon", () => {
      expect(screen.getByTestId("wifioff-icon")).toBeInTheDocument();
    });

    it("does not render the Wifi icon", () => {
      expect(screen.queryByTestId("wifi-icon")).not.toBeInTheDocument();
    });
  });
});
