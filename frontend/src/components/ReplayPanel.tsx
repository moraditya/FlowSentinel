"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  startReplay,
  stopReplay,
  getReplayStatus,
  type ReplayStatus,
} from "@/lib/api";

interface ReplayPanelProps {
  onReplayStateChange?: (isReplaying: boolean) => void;
  onReset?: () => void;
}

export default function ReplayPanel({ onReplayStateChange, onReset }: ReplayPanelProps) {
  const [scenario, setScenario] = useState("mixed");
  const [speed, setSpeed] = useState(2);
  const [status, setStatus] = useState<ReplayStatus | null>(null);
  const [error, setError] = useState<string | null>(null);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isActive = status?.state === "bootstrapping_baseline" || status?.state === "replaying";
  const isCompleted = status?.state === "completed";

  const pollStatus = useCallback(async () => {
    try {
      const s = await getReplayStatus();
      setStatus(s);
      onReplayStateChange?.(
        s.state === "bootstrapping_baseline" || s.state === "replaying"
      );
      if (s.error) setError(s.error);
    } catch {
      // skip
    }
  }, [onReplayStateChange]);

  useEffect(() => {
    pollStatus();
    pollRef.current = setInterval(pollStatus, 2000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [pollStatus]);

  const handleStart = async () => {
    setError(null);
    try {
      const s = await startReplay(scenario, speed);
      setStatus(s);
      onReplayStateChange?.(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start replay");
    }
  };

  const handleStop = async () => {
    setError(null);
    try {
      const s = await stopReplay();
      setStatus(s);
      onReplayStateChange?.(false);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stop replay");
    }
  };

  const stateLabel: Record<string, string> = {
    idle: "IDLE",
    bootstrapping_baseline: "LEARNING BASELINE",
    replaying: "REPLAYING",
    completed: "COMPLETED",
    error: "ERROR",
  };

  const stateColor: Record<string, string> = {
    idle: "text-gray-500",
    bootstrapping_baseline: "text-yellow-400",
    replaying: "text-cyber-cyan",
    completed: "text-cyber-green",
    error: "text-cyber-red",
  };

  const state = status?.state || "idle";

  return (
    <div className="glass rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-3">
        <div className="relative flex items-center justify-center">
          <div className={`w-2.5 h-2.5 rounded-full ${
            isActive ? "bg-cyber-cyan" : isCompleted ? "bg-cyber-green" : "bg-gray-600"
          }`} />
          {isActive && (
            <div className="absolute w-2.5 h-2.5 rounded-full bg-cyber-cyan pulse-dot" />
          )}
        </div>
        <h2 className="text-sm font-bold tracking-[0.2em] text-white uppercase">
          PCAP Replay
        </h2>
        <span className={`text-[0.6rem] font-mono font-bold ml-auto ${stateColor[state]}`}>
          {stateLabel[state] || state.toUpperCase()}
        </span>
      </div>

      {!isActive && !isCompleted && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <select
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
              className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-gray-300 focus:border-cyber-cyan/50 focus:outline-none appearance-none cursor-pointer"
            >
              <option value="mixed">Mixed (baseline + attacks)</option>
              <option value="port_scan">Port Scan</option>
              <option value="brute_force">Brute Force</option>
              <option value="benign">Benign Only</option>
            </select>
            <select
              value={speed}
              onChange={(e) => setSpeed(Number(e.target.value))}
              className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-gray-300 focus:border-cyber-cyan/50 focus:outline-none appearance-none cursor-pointer"
            >
              <option value={1}>1x speed</option>
              <option value={2}>2x speed</option>
              <option value={10}>10x speed</option>
              <option value={50}>50x speed</option>
              <option value={100}>Max speed</option>
            </select>
            <button
              onClick={handleStart}
              className="px-4 py-2 text-xs font-mono font-bold rounded-lg bg-cyber-cyan/10 text-cyber-cyan border border-cyber-cyan/20 hover:bg-cyber-cyan/20 transition-colors"
            >
              START REPLAY
            </button>
          </div>
        </div>
      )}

      {isActive && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-cyber-cyan">
              {state === "bootstrapping_baseline"
                ? "Learning baseline from benign traffic..."
                : `Replaying ${status?.scenario || ""} at ${status?.speed}x...`}
            </span>
            <button
              onClick={handleStop}
              className="px-4 py-2 text-xs font-mono rounded-lg bg-cyber-red/10 text-cyber-red border border-cyber-red/20 hover:bg-cyber-red/20 transition-colors"
            >
              STOP
            </button>
          </div>
        </div>
      )}

      {isCompleted && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-cyber-green">
              Replay complete
            </span>
            <button
              onClick={async () => {
                await stopReplay().catch(() => {});
                setStatus(null);
                setError(null);
                onReplayStateChange?.(false);
                onReset?.();
              }}
              className="ml-auto px-4 py-2 text-xs font-mono rounded-lg bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10 transition-colors"
            >
              RESET
            </button>
          </div>
        </div>
      )}

      {(isActive || isCompleted) && status && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "PACKETS", value: status.packets_replayed.toLocaleString() },
            { label: "FLOWS", value: status.flows_processed.toLocaleString() },
            { label: "ELAPSED", value: `${status.elapsed_seconds}s` },
            { label: "THROUGHPUT", value: `${status.throughput_fps} fps` },
          ].map((stat) => (
            <div key={stat.label} className="bg-black/20 rounded-lg p-3 text-center">
              <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">{stat.label}</p>
              <p className="text-lg font-bold font-mono text-white mt-1">{stat.value}</p>
            </div>
          ))}
        </div>
      )}

      {isCompleted && status?.latency?.p50_ms != null && (
        <div className="flex gap-6 text-[0.6rem] font-mono text-gray-600">
          <span>p50: {status.latency.p50_ms}ms</span>
          <span>p95: {status.latency.p95_ms}ms</span>
          <span>p99: {status.latency.p99_ms}ms</span>
        </div>
      )}

      {error && (
        <div className="bg-cyber-red/5 border border-cyber-red/10 rounded-lg px-4 py-3">
          <p className="text-xs font-mono text-cyber-red">{error}</p>
        </div>
      )}
    </div>
  );
}
