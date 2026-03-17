"use client";

import { useState, useEffect, useCallback, useRef } from "react";
import Header from "@/components/Header";
import LiveCapture from "@/components/LiveCapture";
import ReplayPanel from "@/components/ReplayPanel";
import ThreatFeed from "@/components/ThreatFeed";
import DetectionMetrics from "@/components/DetectionMetrics";
import { getHealth } from "@/lib/api";
import { createLiveSocket, type LiveFlowEvent } from "@/lib/websocket";

type ActivePanel = "live" | "replay";

export default function Dashboard() {
  const [isOnline, setIsOnline] = useState(false);
  const [mode, setMode] = useState<string>("demo");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [capturePhase, setCapturePhase] = useState<"idle" | "baseline" | "monitoring">("idle");
  const [isReplaying, setIsReplaying] = useState(false);
  const [activePanel, setActivePanel] = useState<ActivePanel>("live");
  const [events, setEvents] = useState<LiveFlowEvent[]>([]);
  const [permissionError, setPermissionError] = useState(false);

  const socketRef = useRef<ReturnType<typeof createLiveSocket> | null>(null);

  const fetchInitialData = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const health = await getHealth();
      setIsOnline(true);
      setMode(health.mode || "demo");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to connect to backend");
      setIsOnline(false);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    const socket = createLiveSocket({
      onEvent: (event) => {
        setEvents((prev) => [event, ...prev].slice(0, 200));
      },
    });
    socketRef.current = socket;
    socket.connect();
    return () => socket.disconnect();
  }, []);

  useEffect(() => {
    fetchInitialData();
  }, [fetchInitialData]);

  const handleCaptureStateChange = useCallback((capturing: boolean, phase: "idle" | "baseline" | "monitoring") => {
    setCapturePhase(phase);
    if (phase === "monitoring") setEvents([]);
  }, []);

  const handleCaptureError = useCallback((err: string) => {
    if (err.toLowerCase().includes("permission")) {
      setPermissionError(true);
    }
  }, []);

  const handleReplayStateChange = useCallback((replaying: boolean) => {
    setIsReplaying(replaying);
    if (replaying) setEvents([]);
  }, []);

  const isLiveActive = capturePhase !== "idle";
  const hasEvents = events.length > 0;
  const showFeed = isLiveActive || isReplaying || hasEvents;

  if (error && !isOnline) {
    return (
      <>
        <Header isOnline={false} mode={mode} />
        <main className="max-w-[1920px] mx-auto px-4 sm:px-6 py-8">
          <div className="glass rounded-xl p-8 text-center">
            <p className="text-cyber-red font-mono text-sm mb-2">CONNECTION ERROR</p>
            <p className="text-gray-400 text-sm mb-4">{error}</p>
            <button
              onClick={fetchInitialData}
              className="px-4 py-2 text-xs font-mono rounded-lg bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/20 hover:bg-cyber-cyan/20 transition-colors"
            >
              RETRY CONNECTION
            </button>
          </div>
        </main>
      </>
    );
  }

  return (
    <>
      <Header isOnline={isOnline} mode={mode} />

      <main className="max-w-[1920px] mx-auto px-4 sm:px-6 py-6 space-y-6">
        {/* Panel selector — only when neither is active */}
        {!isLiveActive && !isReplaying && (
          <div className="flex gap-2">
            <button
              onClick={() => setActivePanel("live")}
              className={`px-4 py-2 text-xs font-mono font-bold rounded-lg border transition-colors ${
                activePanel === "live"
                  ? "bg-cyber-green/10 text-cyber-green border-cyber-green/20"
                  : "bg-white/5 text-gray-500 border-white/10 hover:text-white"
              }`}
            >
              LIVE CAPTURE
            </button>
            <button
              onClick={() => { setActivePanel("replay"); setPermissionError(false); }}
              className={`px-4 py-2 text-xs font-mono font-bold rounded-lg border transition-colors ${
                activePanel === "replay"
                  ? "bg-cyber-cyan/10 text-cyber-cyan border-cyber-cyan/20"
                  : "bg-white/5 text-gray-500 border-white/10 hover:text-white"
              }`}
            >
              PCAP REPLAY
            </button>
          </div>
        )}

        {/* Active panel */}
        {(activePanel === "live" || isLiveActive) && !isReplaying && (
          <LiveCapture
            onCaptureStateChange={handleCaptureStateChange}
            onCaptureError={handleCaptureError}
          />
        )}

        {(activePanel === "replay" || isReplaying) && !isLiveActive && (
          <ReplayPanel
            onReplayStateChange={handleReplayStateChange}
            onReset={() => setEvents([])}
          />
        )}

        {/* Permission error with replay fallback */}
        {permissionError && activePanel === "live" && !isLiveActive && (
          <div className="glass rounded-xl p-4 border border-yellow-500/20">
            <p className="text-xs font-mono text-yellow-400 mb-2">
              Capture requires root or CAP_NET_RAW. Try the replay demo instead:
            </p>
            <button
              onClick={() => { setActivePanel("replay"); setPermissionError(false); }}
              className="px-4 py-2 text-xs font-mono font-bold rounded-lg bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/20 hover:bg-cyber-cyan/20 transition-colors"
            >
              SWITCH TO REPLAY DEMO
            </button>
          </div>
        )}

        {/* Live Threat Feed */}
        <ThreatFeed
          events={events}
          isLiveMode={showFeed}
          phase={isReplaying || hasEvents ? "monitoring" : capturePhase}
        />

        {/* Isolation Forest Detection Metrics */}
        <DetectionMetrics isActive={capturePhase === "monitoring"} />
      </main>
    </>
  );
}
