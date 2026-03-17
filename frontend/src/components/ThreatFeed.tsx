"use client";

import { useRef, useEffect, useState } from "react";
import type { LiveFlowEvent } from "@/lib/websocket";
import AlertDrilldown from "./AlertDrilldown";

interface ThreatFeedProps {
  events: LiveFlowEvent[];
  isLiveMode?: boolean;
  phase?: "idle" | "baseline" | "monitoring";
}

export default function ThreatFeed({ events, isLiveMode = false, phase = "idle" }: ThreatFeedProps) {
  const [selectedEvent, setSelectedEvent] = useState<LiveFlowEvent | null>(null);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = 0;
    }
  }, [events.length]);

  return (
    <div className="glass rounded-xl p-5 flex flex-col">
      {/* Header */}
      <div className="flex items-center gap-3 mb-4">
        <div className="relative flex items-center justify-center">
          <div className={`w-2.5 h-2.5 rounded-full ${
            phase === "monitoring" ? "bg-cyber-green"
              : phase === "baseline" ? "bg-yellow-400"
              : "bg-gray-600"
          }`} />
          {isLiveMode && (
            <div className={`absolute w-2.5 h-2.5 rounded-full ${
              phase === "monitoring" ? "bg-cyber-green" : "bg-yellow-400"
            } pulse-dot`} />
          )}
        </div>
        <h2 className="text-sm font-bold tracking-[0.2em] text-white uppercase">
          Live Traffic
        </h2>
        {phase === "baseline" && (
          <span className="text-[0.55rem] font-mono font-bold px-2 py-0.5 rounded bg-yellow-500/15 text-yellow-400">
            LEARNING
          </span>
        )}
        {phase === "monitoring" && (
          <span className="text-[0.55rem] font-mono font-bold px-2 py-0.5 rounded bg-cyber-green/15 text-cyber-green">
            CLASSIFYING
          </span>
        )}
        {events.length > 0 && (
          <span className="text-[0.6rem] font-mono text-gray-500 ml-auto">
            {events.length} flows
          </span>
        )}
      </div>

      {/* Feed */}
      <div
        ref={containerRef}
        className="flex-1 overflow-y-auto space-y-1.5 min-h-0 max-h-[500px]"
      >
        {events.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-40 text-center">
            {phase === "baseline" ? (
              <>
                <div className="w-8 h-8 border-2 border-yellow-400/30 border-t-yellow-400 rounded-full animate-spin mb-3" />
                <p className="text-gray-500 text-sm font-mono">
                  Capturing baseline traffic...
                </p>
                <p className="text-gray-600 text-xs font-mono mt-1">
                  Flows appear after idle timeout (5s)
                </p>
              </>
            ) : phase === "monitoring" ? (
              <>
                <div className="w-8 h-8 border-2 border-cyber-green/30 border-t-cyber-green rounded-full animate-spin mb-3" />
                <p className="text-gray-500 text-sm font-mono">
                  Monitoring — waiting for flows...
                </p>
              </>
            ) : (
              <>
                <p className="text-gray-500 text-sm font-mono">
                  No live data
                </p>
                <p className="text-gray-600 text-xs font-mono mt-1">
                  Start capture above to begin monitoring
                </p>
              </>
            )}
          </div>
        ) : (
          events.map((event, i) => (
            <div
              key={`${event.timestamp}-${i}`}
              onClick={() => phase === "monitoring" && setSelectedEvent(event)}
              className={`feed-item-enter flex items-center gap-3 px-3 py-2 rounded-lg text-xs ${
                phase === "monitoring" ? "cursor-pointer hover:bg-white/5" : ""
              } ${
                phase === "baseline"
                  ? "bg-white/[0.02] border border-white/5"
                  : event.is_attack
                  ? "bg-cyber-red/5 border border-cyber-red/10"
                  : event.is_anomaly
                  ? "bg-yellow-500/5 border border-yellow-500/10"
                  : "bg-cyber-green/5 border border-cyber-green/10"
              }`}
            >
              {/* Timestamp */}
              <span className="font-mono text-gray-500 text-[0.65rem] shrink-0 w-[70px]">
                {new Date(event.timestamp).toLocaleTimeString()}
              </span>

              {/* Protocol */}
              {event.protocol && (
                <span className="font-mono text-gray-600 text-[0.6rem] shrink-0 w-[32px]">
                  {event.protocol}
                </span>
              )}

              {/* Source → Dest */}
              {event.src_ip && (
                <span className="font-mono text-gray-500 text-[0.6rem] shrink-0 hidden sm:inline">
                  {event.src_ip}:{event.src_port} → {event.dst_ip}:{event.dst_port}
                </span>
              )}

              {/* Class or learning label */}
              <span className="font-mono font-medium text-gray-300 truncate flex-1 min-w-0">
                {phase === "baseline"
                  ? "—"
                  : event.predicted_class ?? "normal"}
              </span>

              {/* Anomaly score — only in monitoring */}
              {phase === "monitoring" && event.is_anomaly && (
                <span className="text-[0.55rem] font-mono px-1.5 py-0.5 rounded bg-yellow-500/15 text-yellow-400 shrink-0">
                  {event.anomaly_score.toFixed(3)}
                </span>
              )}

              {/* Confidence bar — only in monitoring */}
              {phase === "monitoring" && event.confidence != null && (
                <div className="w-16 h-1.5 rounded-full bg-black/30 shrink-0 overflow-hidden">
                  <div
                    className={`h-full rounded-full ${
                      event.is_attack ? "bg-cyber-red" : "bg-cyber-green"
                    }`}
                    style={{ width: `${event.confidence * 100}%` }}
                  />
                </div>
              )}

              {/* Badge */}
              <span
                className={`text-[0.6rem] font-mono font-bold px-2 py-0.5 rounded shrink-0 ${
                  phase === "baseline"
                    ? "bg-white/5 text-gray-500"
                    : event.is_attack
                    ? "bg-cyber-red/15 text-cyber-red"
                    : event.is_anomaly
                    ? "bg-yellow-500/15 text-yellow-400"
                    : "bg-cyber-green/15 text-cyber-green"
                }`}
              >
                {phase === "baseline"
                  ? "LEARNING"
                  : event.is_attack
                  ? "THREAT"
                  : event.is_anomaly
                  ? "ANOMALY"
                  : "SAFE"}
              </span>
            </div>
          ))
        )}
      </div>

      {selectedEvent && (
        <AlertDrilldown
          event={selectedEvent}
          onClose={() => setSelectedEvent(null)}
        />
      )}
    </div>
  );
}
