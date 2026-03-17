"use client";

import { Shield, Wifi, WifiOff } from "lucide-react";

interface HeaderProps {
  isOnline: boolean;
  mode?: string;
}

export default function Header({ isOnline, mode }: HeaderProps) {
  return (
    <header className="glass-strong sticky top-0 z-50 px-6 py-3">
      <div className="max-w-[1920px] mx-auto flex items-center justify-between">
        {/* Left: Logo & Title */}
        <div className="flex items-center gap-3">
          <div className="relative">
            <Shield className="w-8 h-8 text-cyber-cyan" strokeWidth={1.5} />
            <div className="absolute inset-0 w-8 h-8 bg-cyber-cyan/20 blur-lg rounded-full" />
          </div>
          <div>
            <h1 className="text-lg font-bold tracking-wider text-white flex items-center gap-2">
              NIDS
              <span className="text-[0.6rem] font-mono font-normal bg-cyber-cyan/10 text-cyber-cyan px-2 py-0.5 rounded border border-cyber-cyan/20">
                v2.0
              </span>
              {mode && (
                <span className={`text-[0.6rem] font-mono font-normal px-2 py-0.5 rounded border ${
                  mode === "production"
                    ? "bg-cyber-red/10 text-cyber-red border-cyber-red/20"
                    : "bg-yellow-500/10 text-yellow-400 border-yellow-500/20"
                }`}>
                  {mode.toUpperCase()}
                </span>
              )}
            </h1>
            <p className="text-[0.65rem] text-gray-500 tracking-widest uppercase font-medium -mt-0.5">
              Network Intrusion Detection System
            </p>
          </div>
        </div>

        {/* Center: Decorative element */}
        <div className="hidden md:flex items-center gap-2 text-gray-600">
          <div className="h-px w-16 bg-gradient-to-r from-transparent to-cyber-cyan/20" />
          <span className="text-[0.6rem] font-mono tracking-[0.3em] text-gray-500 uppercase">
            Threat Intelligence Dashboard
          </span>
          <div className="h-px w-16 bg-gradient-to-l from-transparent to-cyber-cyan/20" />
        </div>

        {/* Right: System Status */}
        <div className="flex items-center gap-3">
          <div
            className={`flex items-center gap-2 px-3 py-1.5 rounded-full border ${
              isOnline
                ? "border-cyber-green/20 bg-cyber-green/5"
                : "border-cyber-red/20 bg-cyber-red/5"
            }`}
          >
            <div className="relative flex items-center justify-center">
              <div
                className={`w-2 h-2 rounded-full ${
                  isOnline ? "bg-cyber-green" : "bg-cyber-red"
                }`}
              />
              {isOnline && (
                <div className="absolute w-2 h-2 rounded-full bg-cyber-green pulse-dot" />
              )}
            </div>
            {isOnline ? (
              <Wifi className="w-3.5 h-3.5 text-cyber-green" />
            ) : (
              <WifiOff className="w-3.5 h-3.5 text-cyber-red" />
            )}
            <span
              className={`text-[0.65rem] font-mono font-semibold tracking-wider ${
                isOnline ? "text-cyber-green" : "text-cyber-red"
              }`}
            >
              {isOnline ? "SYSTEM ONLINE" : "OFFLINE"}
            </span>
          </div>
        </div>
      </div>
    </header>
  );
}
