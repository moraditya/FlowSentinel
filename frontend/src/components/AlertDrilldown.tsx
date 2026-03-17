"use client";

import { useEffect, useState } from "react";
import type { LiveFlowEvent } from "@/lib/websocket";
import {
  getBaselineSummary,
  getReplayBaselineSummary,
  type BaselineSummary,
} from "@/lib/api";

interface AlertDrilldownProps {
  event: LiveFlowEvent;
  onClose: () => void;
}

export default function AlertDrilldown({ event, onClose }: AlertDrilldownProps) {
  const [baseline, setBaseline] = useState<BaselineSummary | null>(null);

  const fromReplay = event.source === "replay";

  useEffect(() => {
    // Each event carries its own source — use replay baseline for replay events
    const fetcher = fromReplay ? getReplayBaselineSummary : getBaselineSummary;
    fetcher()
      .then(setBaseline)
      .catch(() => {
        if (fromReplay) {
          getBaselineSummary().then(setBaseline).catch(() => setBaseline(null));
        } else {
          setBaseline(null);
        }
      });
  }, [fromReplay]);

  // Compute top deviating features
  const deviations: { name: string; value: number; deviation: number }[] = [];
  if (baseline && event.features) {
    for (const [name, value] of Object.entries(event.features)) {
      const b = baseline[name];
      if (b && b.std > 0) {
        deviations.push({
          name,
          value,
          deviation: Math.abs(value - b.mean) / b.std,
        });
      } else if (b) {
        deviations.push({ name, value, deviation: Math.abs(value - b.mean) });
      }
    }
    deviations.sort((a, b) => b.deviation - a.deviation);
  }

  const topDeviations = deviations.slice(0, 5);

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm"
      onClick={onClose}
    >
      <div
        className="glass-strong rounded-xl p-6 w-full max-w-2xl max-h-[80vh] overflow-y-auto space-y-5"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between">
          <h2 className="text-sm font-bold tracking-[0.2em] text-white uppercase">
            Alert Details
          </h2>
          <button
            onClick={onClose}
            className="text-gray-500 hover:text-white text-lg font-mono"
          >
            x
          </button>
        </div>

        {/* Summary */}
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <div className="bg-black/20 rounded-lg p-3">
            <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">SCORE</p>
            <p className={`text-lg font-bold font-mono mt-1 ${
              event.is_anomaly ? "text-yellow-400" : "text-cyber-green"
            }`}>
              {event.anomaly_score.toFixed(4)}
            </p>
          </div>
          <div className="bg-black/20 rounded-lg p-3">
            <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">CLASS</p>
            <p className={`text-lg font-bold font-mono mt-1 ${
              event.is_attack ? "text-cyber-red" : "text-cyber-green"
            }`}>
              {event.predicted_class || "normal"}
            </p>
          </div>
          <div className="bg-black/20 rounded-lg p-3">
            <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">CONFIDENCE</p>
            <p className="text-lg font-bold font-mono text-white mt-1">
              {event.confidence != null ? `${(event.confidence * 100).toFixed(1)}%` : "-"}
            </p>
          </div>
          <div className="bg-black/20 rounded-lg p-3">
            <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">PROTOCOL</p>
            <p className="text-lg font-bold font-mono text-white mt-1">
              {event.protocol || "-"}
            </p>
          </div>
        </div>

        {/* Connection info */}
        <div className="bg-black/10 rounded-lg p-3">
          <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest mb-1">CONNECTION</p>
          <p className="text-xs font-mono text-gray-300">
            {event.src_ip}:{event.src_port} → {event.dst_ip}:{event.dst_port}
          </p>
          <p className="text-[0.6rem] font-mono text-gray-500 mt-1">
            {new Date(event.timestamp).toLocaleString()}
          </p>
        </div>

        {/* Top deviating features */}
        {topDeviations.length > 0 && (
          <div>
            <h3 className="text-xs font-mono text-gray-400 tracking-widest mb-2">
              TOP DEVIATING FEATURES
            </h3>
            <div className="space-y-2">
              {topDeviations.map((d) => {
                const b = baseline?.[d.name];
                return (
                  <div key={d.name} className="flex items-center gap-3 text-xs">
                    <span className="font-mono text-gray-300 w-48 truncate">{d.name}</span>
                    <div className="flex-1 h-2 rounded-full bg-black/30 overflow-hidden">
                      <div
                        className="h-full rounded-full bg-yellow-400/60"
                        style={{ width: `${Math.min(d.deviation / 5 * 100, 100)}%` }}
                      />
                    </div>
                    <span className="font-mono text-yellow-400 w-16 text-right">
                      {d.deviation.toFixed(1)}σ
                    </span>
                    <span className="font-mono text-gray-500 w-24 text-right">
                      {d.value.toFixed(2)} (μ={b?.mean.toFixed(2)})
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}

        {/* Full feature vector */}
        <div>
          <h3 className="text-xs font-mono text-gray-400 tracking-widest mb-2">
            FULL FEATURE VECTOR ({Object.keys(event.features || {}).length} features)
          </h3>
          <div className="grid grid-cols-2 gap-x-4 gap-y-1 max-h-48 overflow-y-auto">
            {Object.entries(event.features || {}).map(([name, value]) => (
              <div key={name} className="flex justify-between text-[0.65rem] font-mono">
                <span className="text-gray-500 truncate">{name}</span>
                <span className="text-gray-300">{typeof value === "number" ? value.toFixed(4) : value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
