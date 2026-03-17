import { NextRequest, NextResponse } from "next/server";

/**
 * Server-side proxy for protected backend endpoints.
 *
 * Forwards requests to the FastAPI backend with the API key injected
 * from a server-only environment variable, keeping it out of the
 * client JS bundle.
 *
 * In production mode (NIDS_MODE=production), the API key MUST be set
 * explicitly — no dev-key fallback.
 */

const BACKEND_URL = process.env.BACKEND_URL || "http://localhost:8000";
const NIDS_MODE = process.env.NIDS_MODE || "demo";

function getApiKey(): string {
  const key = process.env.NIDS_API_KEY;
  if (key) return key;

  if (NIDS_MODE === "production") {
    // No fallback in production — force explicit config
    return "";
  }
  return "dev-key-change-me";
}

const API_KEY = getApiKey();

async function handler(
  req: NextRequest,
  { params }: { params: Promise<{ path: string[] }> }
): Promise<NextResponse> {
  if (NIDS_MODE === "production" && !API_KEY) {
    return NextResponse.json(
      { detail: "NIDS_API_KEY not configured. Set it in the environment." },
      { status: 500 }
    );
  }

  const { path } = await params;
  const backendPath = `/api/${path.join("/")}`;
  const url = `${BACKEND_URL}${backendPath}`;

  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    "X-Api-Key": API_KEY,
  };

  const init: RequestInit = {
    method: req.method,
    headers,
  };

  if (req.method !== "GET" && req.method !== "HEAD") {
    try {
      init.body = await req.text();
    } catch {
      // no body
    }
  }

  try {
    const res = await fetch(url, init);
    const data = await res.json();
    return NextResponse.json(data, { status: res.status });
  } catch {
    return NextResponse.json(
      { detail: "Backend unreachable" },
      { status: 502 }
    );
  }
}

export const GET = handler;
export const POST = handler;
export const PUT = handler;
export const DELETE = handler;
