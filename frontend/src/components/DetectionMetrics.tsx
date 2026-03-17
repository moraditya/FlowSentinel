"use client";

import { useState, useEffect, useRef } from "react";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import { getDetectionStats, type DetectionStats } from "@/lib/api";

const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

interface DetectionMetricsProps {
  isActive: boolean;
}

export default function DetectionMetrics({ isActive }: DetectionMetricsProps) {
  const [stats, setStats] = useState<DetectionStats | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (!isActive) {
      setStats(null);
      return;
    }

    const poll = async () => {
      try {
        const data = await getDetectionStats();
        setStats(data);
      } catch {
        // skip
      }
    };

    poll();
    pollRef.current = setInterval(poll, 3000);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [isActive]);

  if (!isActive || !stats || stats.total_flows_scored === 0) {
    return (
      <div className="glass rounded-xl p-5">
        <h2 className="text-sm font-bold tracking-[0.2em] text-white uppercase mb-4">
          Isolation Forest Metrics
        </h2>
        <div className="flex items-center justify-center h-32 text-gray-600 text-sm font-mono">
          {isActive
            ? "Collecting detection data..."
            : "Start monitoring to see detection metrics"}
        </div>
      </div>
    );
  }

  const anomalyPct = (stats.anomaly_rate * 100).toFixed(1);
  const normalPct = ((1 - stats.anomaly_rate) * 100).toFixed(1);

  // Score distribution chart data
  const distData = stats.score_distribution.map((bin) => ({
    range: `${bin.range_start.toFixed(2)}`,
    count: bin.count,
    isAnomaly: bin.range_end < 0,
  }));

  // Classification breakdown
  const classEntries = Object.entries(stats.classifications).sort(
    ([, a], [, b]) => b - a
  );

  return (
    <div className="glass rounded-xl p-5 space-y-5">
      <div className="flex items-center gap-3">
        <h2 className="text-sm font-bold tracking-[0.2em] text-white uppercase">
          Isolation Forest Metrics
        </h2>
        <span className="text-[0.55rem] font-mono font-bold px-2 py-0.5 rounded bg-cyber-green/15 text-cyber-green">
          LIVE
        </span>
        <a
          href={`${API_BASE}/api/report/csv`}
          download
          className="ml-auto px-3 py-1 text-[0.6rem] font-mono rounded-lg bg-white/5 text-gray-400 border border-white/10 hover:bg-white/10 hover:text-white transition-colors"
        >
          EXPORT CSV
        </a>
      </div>

      {/* Key stats */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-black/20 rounded-lg p-3 text-center">
          <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">FLOWS SCORED</p>
          <p className="text-xl font-bold font-mono text-cyber-cyan mt-1">
            {stats.total_flows_scored.toLocaleString()}
          </p>
        </div>
        <div className="bg-black/20 rounded-lg p-3 text-center">
          <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">ANOMALIES</p>
          <p className="text-xl font-bold font-mono text-yellow-400 mt-1">
            {stats.anomalies_detected.toLocaleString()}
          </p>
        </div>
        <div className="bg-black/20 rounded-lg p-3 text-center">
          <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">ANOMALY RATE</p>
          <p className={`text-xl font-bold font-mono mt-1 ${
            stats.anomaly_rate > 0.3 ? "text-cyber-red" : stats.anomaly_rate > 0.1 ? "text-yellow-400" : "text-cyber-green"
          }`}>
            {anomalyPct}%
          </p>
        </div>
        <div className="bg-black/20 rounded-lg p-3 text-center">
          <p className="text-[0.6rem] font-mono text-gray-500 tracking-widest">THREATS</p>
          <p className="text-xl font-bold font-mono text-cyber-red mt-1">
            {stats.threats_classified.toLocaleString()}
          </p>
        </div>
      </div>

      {/* Anomaly vs Normal bar */}
      <div>
        <div className="flex justify-between text-[0.6rem] font-mono text-gray-500 mb-1">
          <span>Normal ({normalPct}%)</span>
          <span>Anomalous ({anomalyPct}%)</span>
        </div>
        <div className="h-3 rounded-full bg-black/30 overflow-hidden flex">
          <div
            className="h-full bg-cyber-green transition-all duration-500"
            style={{ width: `${100 - stats.anomaly_rate * 100}%` }}
          />
          <div
            className="h-full bg-yellow-400 transition-all duration-500"
            style={{ width: `${stats.anomaly_rate * 100}%` }}
          />
        </div>
      </div>

      {/* Score distribution */}
      {distData.length > 1 && (
        <div>
          <h3 className="text-xs font-mono text-gray-400 tracking-widest mb-2">
            ANOMALY SCORE DISTRIBUTION
          </h3>
          <p className="text-[0.6rem] font-mono text-gray-600 mb-2">
            Negative scores = anomalous | Positive scores = normal | Mean: {stats.mean_score.toFixed(4)}
          </p>
          <div className="h-[180px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={distData}>
                <XAxis
                  dataKey="range"
                  tick={{ fill: "#9ca3af", fontSize: 9, fontFamily: "monospace" }}
                  axisLine={{ stroke: "#374151" }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#9ca3af", fontSize: 9, fontFamily: "monospace" }}
                  axisLine={{ stroke: "#374151" }}
                  tickLine={false}
                />
                <Tooltip
                  contentStyle={{
                    background: "#111827",
                    border: "1px solid rgba(255,255,255,0.1)",
                    borderRadius: "8px",
                    fontSize: "11px",
                    fontFamily: "monospace",
                  }}
                />
                <Bar dataKey="count" radius={[3, 3, 0, 0]}>
                  {distData.map((entry, i) => (
                    <Cell
                      key={i}
                      fill={entry.isAnomaly ? "#eab308" : "#00ff88"}
                      opacity={0.7}
                    />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Classification breakdown */}
      {classEntries.length > 0 && (
        <div>
          <h3 className="text-xs font-mono text-gray-400 tracking-widest mb-2">
            THREAT CLASSIFICATIONS (XGBoost)
          </h3>
          <div className="space-y-1.5">
            {classEntries.map(([cls, count]) => {
              const pct = (count / stats.anomalies_detected) * 100;
              return (
                <div key={cls} className="flex items-center gap-3 text-xs">
                  <span className="font-mono text-gray-300 w-28 truncate">{cls}</span>
                  <div className="flex-1 h-2 rounded-full bg-black/30 overflow-hidden">
                    <div
                      className="h-full rounded-full bg-cyber-red/60"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="font-mono text-gray-500 w-16 text-right">
                    {count} ({pct.toFixed(0)}%)
                  </span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Score stats */}
      <div className="flex gap-6 text-[0.6rem] font-mono text-gray-600">
        <span>Min score: {stats.min_score.toFixed(4)}</span>
        <span>Mean: {stats.mean_score.toFixed(4)}</span>
        <span>Max: {stats.max_score.toFixed(4)}</span>
      </div>
    </div>
  );
}
