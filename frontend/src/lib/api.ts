const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

/**
 * Protected endpoints are proxied through the Next.js server so the
 * API key never appears in the client bundle.
 */
const PROXY_BASE = "/api/proxy";

// ── Type Definitions ────────────────────────────────────────────────────────

export interface HealthResponse {
  status: string;
  model_loaded: boolean;
  model_type: string;
  mode: string;
}

export interface ClassReport {
  precision: number;
  recall: number;
  "f1-score": number;
  support: number;
}

export interface MetricsResponse {
  accuracy: number;
  classification_report: Record<string, ClassReport | number>;
}

export interface Feature {
  feature: string;
  importance: number;
}

export interface ConfusionMatrixResponse {
  labels: string[];
  matrix: number[][];
}

export interface DatasetStats {
  total_samples: number;
  attack_distribution: Record<string, number>;
}

export interface PredictionRequest {
  features: Record<string, number>;
}

export interface PredictionResponse {
  predicted_class: string;
  confidence: number;
  is_attack: boolean;
  probabilities: Record<string, number>;
}

export interface SimulatedEvent {
  timestamp: string;
  predicted_class: string;
  confidence: number;
  is_attack: boolean;
  features: Record<string, number>;
}

// ── API Functions ───────────────────────────────────────────────────────────

async function fetchAPI<T>(endpoint: string, options?: RequestInit): Promise<T> {
  // Proxy routes are relative to the Next.js server; direct API calls go to the backend.
  const url = endpoint.startsWith(PROXY_BASE)
    ? endpoint
    : `${API_BASE}${endpoint}`;

  try {
    const res = await fetch(url, {
      ...options,
      headers: {
        "Content-Type": "application/json",
        ...options?.headers,
      },
    });

    if (!res.ok) {
      throw new Error(`API Error: ${res.status} ${res.statusText}`);
    }

    return await res.json();
  } catch (error) {
    if (error instanceof TypeError && error.message.includes("fetch")) {
      throw new Error("Unable to connect to the NIDS backend. Is it running?");
    }
    throw error;
  }
}

export async function getHealth(): Promise<HealthResponse> {
  return fetchAPI<HealthResponse>("/api/health");
}

export async function getMetrics(): Promise<MetricsResponse> {
  return fetchAPI<MetricsResponse>("/api/metrics");
}

export async function getFeatureImportance(): Promise<Feature[]> {
  return fetchAPI<Feature[]>("/api/feature-importance");
}

export async function getConfusionMatrix(): Promise<ConfusionMatrixResponse> {
  return fetchAPI<ConfusionMatrixResponse>("/api/confusion-matrix");
}

export async function getDatasetStats(): Promise<DatasetStats> {
  return fetchAPI<DatasetStats>("/api/dataset/stats");
}

export async function predict(
  features: Record<string, number>
): Promise<PredictionResponse> {
  return fetchAPI<PredictionResponse>(`${PROXY_BASE}/predict`, {
    method: "POST",
    body: JSON.stringify({ features }),
  });
}

export async function simulate(count: number = 10): Promise<SimulatedEvent[]> {
  return fetchAPI<SimulatedEvent[]>(`/api/simulate?count=${count}`);
}

export async function getFeatureNames(): Promise<string[]> {
  return fetchAPI<string[]>("/api/feature-names");
}

// ── Capture Types & Functions ──────────────────────────────────────────────

export interface CaptureStatusResponse {
  is_capturing: boolean;
  interface: string | null;
  packets_captured: number;
  flows_analyzed: number;
  threats_detected: number;
  uptime_seconds: number;
  error: string | null;
}

export interface BaselineStatusResponse {
  status: string;
  samples_collected: number;
  seconds_remaining: number;
  duration_seconds: number;
  message: string;
}

export async function startCapture(
  iface: string,
  bpfFilter: string
): Promise<CaptureStatusResponse> {
  return fetchAPI<CaptureStatusResponse>(`${PROXY_BASE}/capture/start`, {
    method: "POST",
    body: JSON.stringify({ interface: iface, bpf_filter: bpfFilter }),
  });
}

export async function stopCapture(): Promise<CaptureStatusResponse> {
  return fetchAPI<CaptureStatusResponse>(`${PROXY_BASE}/capture/stop`, {
    method: "POST",
  });
}

export async function getCaptureStatus(): Promise<CaptureStatusResponse> {
  return fetchAPI<CaptureStatusResponse>("/api/capture/status");
}

export async function collectBaseline(
  durationSeconds: number
): Promise<BaselineStatusResponse> {
  return fetchAPI<BaselineStatusResponse>(`${PROXY_BASE}/baseline/collect`, {
    method: "POST",
    body: JSON.stringify({ duration_seconds: durationSeconds }),
  });
}

export async function finishBaseline(): Promise<BaselineStatusResponse> {
  return fetchAPI<BaselineStatusResponse>(`${PROXY_BASE}/baseline/finish`, {
    method: "POST",
  });
}

export async function getBaselineStatus(): Promise<BaselineStatusResponse> {
  return fetchAPI<BaselineStatusResponse>("/api/baseline/status");
}

export interface DetectionStats {
  total_flows_scored: number;
  anomalies_detected: number;
  anomaly_rate: number;
  threats_classified: number;
  score_distribution: { range_start: number; range_end: number; count: number }[];
  classifications: Record<string, number>;
  mean_score: number;
  min_score: number;
  max_score: number;
}

export async function getDetectionStats(): Promise<DetectionStats> {
  return fetchAPI<DetectionStats>("/api/detection/stats");
}

// ── Replay ─────────────────────────────────────────────────────────────────

export interface ReplayStatus {
  state: string;
  scenario: string | null;
  speed: number;
  packets_replayed: number;
  flows_processed: number;
  elapsed_seconds: number;
  throughput_fps: number;
  latency: Record<string, number>;
  stage_timing: Record<string, Record<string, number>>;
  error: string | null;
}

export async function startReplay(
  scenario: string,
  speed: number
): Promise<ReplayStatus> {
  return fetchAPI<ReplayStatus>(
    `${PROXY_BASE}/replay/start?scenario=${scenario}&speed=${speed}`,
    { method: "POST" }
  );
}

export async function stopReplay(): Promise<ReplayStatus> {
  return fetchAPI<ReplayStatus>(`${PROXY_BASE}/replay/stop`, {
    method: "POST",
  });
}

export async function getReplayStatus(): Promise<ReplayStatus> {
  return fetchAPI<ReplayStatus>("/api/replay/status");
}

export async function getReplayBaselineSummary(): Promise<BaselineSummary> {
  return fetchAPI<BaselineSummary>("/api/replay/baseline-summary");
}

// ── Baseline Summary ───────────────────────────────────────────────────────

export type BaselineSummary = Record<string, { mean: number; std: number }>;

export async function getBaselineSummary(): Promise<BaselineSummary> {
  return fetchAPI<BaselineSummary>("/api/baseline/summary");
}

