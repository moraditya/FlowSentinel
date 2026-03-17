import {
  getHealth,
  getMetrics,
  getFeatureImportance,
  getConfusionMatrix,
  getDatasetStats,
  predict,
  simulate,
  getFeatureNames,
} from "@/lib/api";

// Store original fetch
const originalFetch = global.fetch;

beforeEach(() => {
  global.fetch = jest.fn();
});

afterAll(() => {
  global.fetch = originalFetch;
});

const mockFetch = () => global.fetch as jest.MockedFunction<typeof fetch>;

function mockJsonResponse(data: unknown, status = 200, statusText = "OK") {
  mockFetch().mockResolvedValueOnce({
    ok: status >= 200 && status < 300,
    status,
    statusText,
    json: async () => data,
  } as Response);
}

function mockNetworkError() {
  mockFetch().mockRejectedValueOnce(
    Object.assign(new TypeError("Failed to fetch"), {
      message: "Failed to fetch",
    })
  );
}

describe("API Client", () => {
  // ─── getHealth ────────────────────────────────────────────────────────────

  describe("getHealth", () => {
    it("calls the correct endpoint", async () => {
      const data = { status: "healthy", model_loaded: true, mode: "demo" };
      mockJsonResponse(data);

      const result = await getHealth();

      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/health",
        expect.objectContaining({
          headers: expect.objectContaining({
            "Content-Type": "application/json",
          }),
        })
      );
      expect(result).toEqual(data);
    });
  });

  // ─── getMetrics ───────────────────────────────────────────────────────────

  describe("getMetrics", () => {
    it("calls /api/metrics", async () => {
      const data = { accuracy: 0.93, classification_report: {} };
      mockJsonResponse(data);

      const result = await getMetrics();

      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/metrics",
        expect.any(Object)
      );
      expect(result).toEqual(data);
    });
  });

  // ─── getFeatureImportance ─────────────────────────────────────────────────

  describe("getFeatureImportance", () => {
    it("calls /api/feature-importance", async () => {
      const data = [{ feature: "src_bytes", importance: 0.15 }];
      mockJsonResponse(data);

      const result = await getFeatureImportance();

      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/feature-importance",
        expect.any(Object)
      );
      expect(result).toEqual(data);
    });
  });

  // ─── getConfusionMatrix ───────────────────────────────────────────────────

  describe("getConfusionMatrix", () => {
    it("calls /api/confusion-matrix", async () => {
      const data = { labels: ["Normal", "Attack"], matrix: [[95, 5], [3, 97]] };
      mockJsonResponse(data);

      const result = await getConfusionMatrix();

      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/confusion-matrix",
        expect.any(Object)
      );
      expect(result).toEqual(data);
    });
  });

  // ─── getDatasetStats ──────────────────────────────────────────────────────

  describe("getDatasetStats", () => {
    it("calls /api/dataset/stats", async () => {
      const data = { total_samples: 125973, attack_distribution: {} };
      mockJsonResponse(data);

      const result = await getDatasetStats();

      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/dataset/stats",
        expect.any(Object)
      );
      expect(result).toEqual(data);
    });
  });

  // ─── predict ──────────────────────────────────────────────────────────────

  describe("predict", () => {
    it("sends POST through proxy to predict", async () => {
      const responseData = { predicted_class: "DoS", confidence: 0.95 };
      mockJsonResponse(responseData);

      const features = { src_bytes: 1000, dst_bytes: 0 };
      const result = await predict(features);

      expect(mockFetch()).toHaveBeenCalledWith(
        "/api/proxy/predict",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ features }),
        })
      );
      expect(result).toEqual(responseData);
    });
  });

  // ─── simulate ─────────────────────────────────────────────────────────────

  describe("simulate", () => {
    it("calls /api/simulate with default count", async () => {
      mockJsonResponse([]);
      await simulate();
      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/simulate?count=10",
        expect.any(Object)
      );
    });

    it("calls /api/simulate with custom count", async () => {
      mockJsonResponse([]);
      await simulate(5);
      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/simulate?count=5",
        expect.any(Object)
      );
    });
  });

  // ─── getFeatureNames ─────────────────────────────────────────────────────

  describe("getFeatureNames", () => {
    it("calls /api/feature-names", async () => {
      const data = ["src_bytes", "dst_bytes", "duration"];
      mockJsonResponse(data);

      const result = await getFeatureNames();

      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/feature-names",
        expect.any(Object)
      );
      expect(result).toEqual(data);
    });
  });

  // ─── Capture & Baseline ──────────────────────────────────────────────────

  describe("startCapture", () => {
    it("sends POST through proxy to start capture", async () => {
      const { startCapture } = await import("@/lib/api");
      mockJsonResponse({ is_capturing: true });

      await startCapture("en0", "tcp port 80");

      expect(mockFetch()).toHaveBeenCalledWith(
        "/api/proxy/capture/start",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ interface: "en0", bpf_filter: "tcp port 80" }),
        })
      );
    });
  });

  describe("stopCapture", () => {
    it("sends POST through proxy to stop capture", async () => {
      const { stopCapture } = await import("@/lib/api");
      mockJsonResponse({ is_capturing: false });

      await stopCapture();

      expect(mockFetch()).toHaveBeenCalledWith(
        "/api/proxy/capture/stop",
        expect.objectContaining({
          method: "POST",
        })
      );
    });
  });

  describe("getCaptureStatus", () => {
    it("calls GET /api/capture/status", async () => {
      const { getCaptureStatus } = await import("@/lib/api");
      mockJsonResponse({ is_capturing: false });

      await getCaptureStatus();

      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/capture/status",
        expect.any(Object)
      );
    });
  });

  describe("collectBaseline", () => {
    it("sends POST through proxy to collect baseline", async () => {
      const { collectBaseline } = await import("@/lib/api");
      mockJsonResponse({ status: "collecting" });

      await collectBaseline(60);

      expect(mockFetch()).toHaveBeenCalledWith(
        "/api/proxy/baseline/collect",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ duration_seconds: 60 }),
        })
      );
    });
  });

  describe("finishBaseline", () => {
    it("sends POST through proxy to finish baseline", async () => {
      const { finishBaseline } = await import("@/lib/api");
      mockJsonResponse({ status: "ready", samples_collected: 50 });

      const result = await finishBaseline();

      expect(mockFetch()).toHaveBeenCalledWith(
        "/api/proxy/baseline/finish",
        expect.objectContaining({
          method: "POST",
        })
      );
      expect(result.status).toBe("ready");
    });
  });

  describe("getDetectionStats", () => {
    it("calls GET /api/detection/stats", async () => {
      const { getDetectionStats } = await import("@/lib/api");
      const data = { total_flows_scored: 100, anomalies_detected: 5 };
      mockJsonResponse(data);

      const result = await getDetectionStats();

      expect(mockFetch()).toHaveBeenCalledWith(
        "http://localhost:8000/api/detection/stats",
        expect.any(Object)
      );
      expect(result).toEqual(data);
    });
  });

  // ─── Error handling ───────────────────────────────────────────────────────

  describe("error handling", () => {
    it("throws on non-ok HTTP responses", async () => {
      mockJsonResponse({}, 500, "Internal Server Error");
      await expect(getHealth()).rejects.toThrow("API Error: 500 Internal Server Error");
    });

    it("throws on 404", async () => {
      mockJsonResponse({}, 404, "Not Found");
      await expect(getMetrics()).rejects.toThrow("API Error: 404 Not Found");
    });

    it("throws connection error when fetch fails", async () => {
      mockNetworkError();
      await expect(getHealth()).rejects.toThrow(
        "Unable to connect to the NIDS backend. Is it running?"
      );
    });

    it("re-throws non-fetch errors as-is", async () => {
      mockFetch().mockRejectedValueOnce(new Error("Something unexpected"));
      await expect(getHealth()).rejects.toThrow("Something unexpected");
    });

    it("includes Content-Type header in all requests", async () => {
      mockJsonResponse({ status: "ok", model_loaded: true, mode: "demo" });
      await getHealth();

      const callArgs = mockFetch().mock.calls[0];
      const options = callArgs[1] as RequestInit;
      expect((options.headers as Record<string, string>)["Content-Type"]).toBe(
        "application/json"
      );
    });
  });
});
