"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import {
  startCapture,
  stopCapture,
  getCaptureStatus,
  collectBaseline,
  getBaselineStatus,
  type CaptureStatusResponse,
  type BaselineStatusResponse,
} from "@/lib/api";

type Phase = "idle" | "baseline" | "monitoring";

interface LiveCaptureProps {
  onCaptureStateChange?: (isCapturing: boolean, phase: Phase) => void;
  onCaptureError?: (error: string) => void;
}

/**
 * Derive the UI phase from backend state so a page refresh always
 * reconstructs the correct view.
 */
function derivePhase(
  cap: CaptureStatusResponse,
  base: BaselineStatusResponse,
): Phase {
  if (!cap.is_capturing) return "idle";
  if (base.status === "collecting") return "baseline";
  if (base.status === "ready") return "monitoring";
  // Capture is running but no baseline — still idle-ish (pre-baseline)
  return "idle";
}

export default function LiveCapture({ onCaptureStateChange, onCaptureError }: LiveCaptureProps) {
  const [iface, setIface] = useState("en0");
  const DURATION_OPTIONS = [
    { label: "60s", value: 60 },
    { label: "2 min", value: 120 },
    { label: "5 min", value: 300 },
    { label: "10 min", value: 600 },
    { label: "30 min", value: 1800 },
  ];
  const [baselineDuration, setBaselineDuration] = useState(60);
  const [phase, setPhase] = useState<Phase>("idle");

  const [captureStatus, setCaptureStatus] = useState<CaptureStatusResponse>({
    is_capturing: false,
    interface: null,
    packets_captured: 0,
    flows_analyzed: 0,
    threats_detected: 0,
    uptime_seconds: 0,
    error: null,
  });
  const [baselineStatus, setBaselineStatus] = useState<BaselineStatusResponse>({
    status: "not_collected",
    samples_collected: 0,
    seconds_remaining: 0,
    duration_seconds: 0,
    message: "",
  });
  const [error, setError] = useState<string | null>(null);

  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const pollStatus = useCallback(async () => {
    try {
      const [cap, base] = await Promise.all([
        getCaptureStatus(),
        getBaselineStatus(),
      ]);
      setCaptureStatus(cap);
      setBaselineStatus(base);

      // Always derive phase from backend state — survives page refresh
      const derived = derivePhase(cap, base);
      setPhase(derived);
      onCaptureStateChange?.(cap.is_capturing, derived);

      if (cap.error && !cap.is_capturing) {
        setError(cap.error);
      }
    } catch {
      // silently skip poll failures
    }
  }, [onCaptureStateChange]);

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
      // Step 1: Start capture
      const capRes = await startCapture(iface, "");
      setCaptureStatus(capRes);

      if (!capRes.is_capturing && capRes.error) {
        setError(capRes.error);
        onCaptureError?.(capRes.error);
        return;
      }

      // Step 2: Begin baseline collection (backend owns the timer)
      const baseRes = await collectBaseline(baselineDuration);
      setBaselineStatus(baseRes);

      // Optimistic phase update (poll will confirm)
      setPhase("baseline");
      onCaptureStateChange?.(true, "baseline");
    } catch (err) {
      const msg = err instanceof Error ? err.message : "Failed to start";
      setError(msg);
      onCaptureError?.(msg);
    }
  };

  const handleStop = async () => {
    setError(null);
    try {
      const res = await stopCapture();
      setCaptureStatus(res);
      setPhase("idle");
      onCaptureStateChange?.(false, "idle");
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to stop");
    }
  };

  const formatUptime = (s: number) => {
    const mins = Math.floor(s / 60);
    const secs = Math.floor(s % 60);
    return `${mins}m ${secs}s`;
  };

  const phaseLabel = {
    idle: "IDLE",
    baseline: "COLLECTING BASELINE",
    monitoring: "MONITORING",
  };

  const phaseColor = {
    idle: "text-gray-500",
    baseline: "text-yellow-400",
    monitoring: "text-cyber-green",
  };

  // Progress from backend
  const progressPct =
    phase === "baseline" && baselineStatus.duration_seconds > 0
      ? ((baselineStatus.duration_seconds - baselineStatus.seconds_remaining) /
          baselineStatus.duration_seconds) *
        100
      : 0;

  const secondsLeft = baselineStatus.seconds_remaining;

  return (
    <div className="glass rounded-xl p-5 space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="relative flex items-center justify-center">
          <div
            className={`w-2.5 h-2.5 rounded-full ${
              phase === "monitoring" ? "bg-cyber-green"
                : phase === "baseline" ? "bg-yellow-400"
                : "bg-gray-600"
            }`}
          />
          {phase !== "idle" && (
            <div className={`absolute w-2.5 h-2.5 rounded-full ${
              phase === "monitoring" ? "bg-cyber-green" : "bg-yellow-400"
            } pulse-dot`} />
          )}
        </div>
        <h2 className="text-sm font-bold tracking-[0.2em] text-white uppercase">
          Network Monitor
        </h2>
        <span className={`text-[0.6rem] font-mono font-bold ml-auto ${phaseColor[phase]}`}>
          {phaseLabel[phase]}
        </span>
      </div>

      {/* Controls — shown when idle */}
      {phase === "idle" && (
        <div className="space-y-3">
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <input
              type="text"
              value={iface}
              onChange={(e) => setIface(e.target.value)}
              placeholder="Interface"
              className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-gray-300 focus:border-cyber-cyan/50 focus:outline-none"
            />
            <select
              value={baselineDuration}
              onChange={(e) => setBaselineDuration(Number(e.target.value))}
              className="bg-black/30 border border-white/10 rounded-lg px-3 py-2 text-xs font-mono text-gray-300 focus:border-cyber-cyan/50 focus:outline-none appearance-none cursor-pointer"
            >
              {DURATION_OPTIONS.map((opt) => (
                <option key={opt.value} value={opt.value}>
                  {opt.label} baseline
                </option>
              ))}
            </select>
            <button
              onClick={handleStart}
              className="px-4 py-2 text-xs font-mono font-bold rounded-lg bg-cyber-green/10 text-cyber-green border border-cyber-green/20 hover:bg-cyber-green/20 transition-colors"
            >
              START CAPTURE
            </button>
          </div>
        </div>
      )}

      {/* Baseline progress */}
      {phase === "baseline" && (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs font-mono text-yellow-400">
              Learning your normal traffic pattern...
            </span>
            <span className="text-xs font-mono text-yellow-400 font-bold">
              {secondsLeft >= 60
                ? `${Math.floor(secondsLeft / 60)}m ${secondsLeft % 60}s`
                : `${secondsLeft}s`} remaining
            </span>
          </div>
          <div className="h-2 rounded-full bg-black/30 overflow-hidden">
            <div
              className="h-full rounded-full bg-yellow-400 transition-all duration-1000"
              style={{ width: `${progressPct}%` }}
            />
          </div>
          <div className="flex items-center justify-between">
            <span className="text-[0.6rem] font-mono text-gray-500">
              {baselineStatus.samples_collected} samples collected
            </span>
            <button
              onClick={handleStop}
              className="px-4 py-2 text-xs font-mono rounded-lg bg-cyber-red/10 text-cyber-red border border-cyber-red/20 hover:bg-cyber-red/20 transition-colors"
            >
              CANCEL
            </button>
          </div>
        </div>
      )}

      {/* Monitoring active */}
      {phase === "monitoring" && (
        <div className="space-y-3">
          <div className="flex items-center gap-3">
            <span className="text-xs font-mono text-cyber-green">
              Isolation Forest active — classifying live traffic
            </span>
            <button
              onClick={handleStop}
              className="ml-auto px-4 py-2 text-xs font-mono rounded-lg bg-cyber-red/10 text-cyber-red border border-cyber-red/20 hover:bg-cyber-red/20 transition-colors"
            >
              STOP
            </button>
          </div>
        </div>
      )}

      {/* Stats Grid — shown when active */}
      {phase !== "idle" && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "PACKETS", value: captureStatus.packets_captured.toLocaleString() },
            { label: "FLOWS", value: captureStatus.flows_analyzed.toLocaleString() },
            { label: "THREATS", value: captureStatus.threats_detected.toLocaleString() },
            { label: "UPTIME", value: formatUptime(captureStatus.uptime_seconds) },
          ].map((stat) => (
            <div key={stat.label} className="bg-black/20 rounded-lg p-3 text-center">
              <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">
                {stat.label}
              </p>
              <p className="text-lg font-bold font-mono text-white mt-1">{stat.value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Error */}
      {error && (
        <div className="bg-cyber-red/5 border border-cyber-red/10 rounded-lg px-4 py-3">
          <p className="text-xs font-mono text-cyber-red">{error}</p>
        </div>
      )}
    </div>
  );
}
