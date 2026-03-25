# NIDS Platform

Real-time network anomaly detection platform with live packet capture, PCAP replay, and benchmarked unsupervised baselines across two modern IDS datasets. See here: http://18.117.98.102:3000/ 

The system captures live traffic, learns what "normal" looks like from the user's own baseline, and flags unusual flows using an Isolation Forest. Five unsupervised detection methods are benchmarked against a supervised ceiling on UNSW-NB15 and CIC-IDS-2018. A PCAP replay engine enables deterministic demos without root access.

```
make setup && make demo    # see alerts in the dashboard in 30 seconds
```

---

## Benchmark Results

Evaluated on 28 packet-observable features. Unsupervised models trained on normal-only traffic. Supervised oracle trained on labeled data (upper bound, not deployable).

**UNSW-NB15** (257k flows, 39 native features)

| Model | Class | F1 | PR-AUC | FP/10k |
|---|---|---|---|---|
| XGBoost | Supervised ceiling | 0.958 | 0.995 | 236.0 |
| **LOF** | **Unsupervised** | **0.685** | **0.868** | **191.3** |
| OCSVM | Unsupervised | 0.530 | 0.827 | 189.4 |
| Isolation Forest | Unsupervised | 0.415 | 0.833 | 180.5 |
| Z-score | Unsupervised | 0.395 | 0.829 | 177.4 |
| PCA | Unsupervised | 0.273 | 0.768 | 183.6 |

**CIC-IDS-2018** (500k sampled flows, 78 native features)

| Model | Class | F1 | PR-AUC | FP/10k |
|---|---|---|---|---|
| XGBoost | Supervised ceiling | 0.964 | 0.978 | 4.2 |
| **LOF** | **Unsupervised** | **0.543** | **0.605** | **454.3** |
| OCSVM | Unsupervised | 0.144 | 0.191 | 415.9 |
| PCA | Unsupervised | 0.055 | 0.340 | 427.1 |
| IF | Unsupervised | 0.014 | 0.160 | 409.0 |
| Z-score | Unsupervised | 0.013 | 0.131 | 413.6 |

LOF is the strongest unsupervised baseline on both datasets. IF is competitive on UNSW-NB15 but struggles on CIC-IDS-2018's high-dimensional feature space. The supervised ceiling shows what's achievable with labeled data. Full report: [`reports/evaluation.md`](reports/evaluation.md).

---

## Architecture

```
                         ┌─ live sniff (CaptureEngine)
  ingest_packet(pkt) ◄───┤
                         └─ PCAP replay (ReplayEngine)
         │
    FlowAggregator          5-tuple, 5s idle / 30s active timeout
         │
    FeatureExtractor         28 observable features
         │
    Isolation Forest         trained on user's baseline (unsupervised)
         │ anomaly?
         ▼
    XGBoost (optional)       supplementary classifier (if artifacts present)
         │
    broadcaster.publish      thread-safe async queue
         │
    WebSocket /ws/live  ───► Next.js Dashboard
```

**Key design decisions:**
- Shared `ingest_packet()` seam for both live capture and PCAP replay
- Thread-safe `CaptureEngine` with `threading.Lock` on all shared state
- Backend-owned baseline timer (no client-side countdown)
- Server-side API proxy (no secrets in client bundle)
- Per-stage latency instrumentation (parse/features/score/classify/publish)
- Demo and production modes with strict startup validation

## Quick Start

### One-command demo (no root needed)

```bash
make setup    # install backend venv + frontend deps
make demo     # start backend, replay mixed PCAP scenario
```

### Manual setup

**Backend:**
```bash
cd backend
python3 -m venv venv && source venv/bin/activate
pip install -r requirements-dev.txt
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

**Frontend:**
```bash
cd frontend
npm ci
npm run dev
```

**Docker Compose (dev):**
```bash
cp .env.example .env
docker compose up --build
```

Dashboard at `http://localhost:3001`, API at `http://localhost:8000`.

## Dashboard

| Panel | Description |
|---|---|
| **Network Monitor / Replay** | Start live capture or PCAP replay, select interface/scenario, collect baseline |
| **Live Traffic Feed** | Scrolling flow list with anomaly scores. Click any alert for drilldown. |
| **Alert Drilldown** | Full 28-feature vector, top 5 deviating features vs baseline, classification confidence |
| **Detection Metrics** | Anomaly rate, score distribution, classification breakdown, CSV export |

## API Endpoints

| Method | Endpoint | Auth | Description |
|---|---|---|---|
| GET | `/api/health` | No | Liveness probe + mode (demo/production) |
| GET | `/api/feature-names` | No | 28 observable feature names |
| GET | `/api/evaluation` | No | Cached evaluation results |
| GET | `/api/metrics` | No | Classifier accuracy (503 if no model) |
| GET | `/api/feature-importance` | No | Feature importance scores |
| GET | `/api/confusion-matrix` | No | Multiclass confusion matrix |
| GET | `/api/dataset/stats` | No | Training dataset statistics |
| POST | `/api/predict` | Key | Classify a single feature vector |
| POST | `/api/predict/batch` | Key | Classify a batch of feature vectors |
| POST | `/api/capture/start` | Key | Start live capture (preflight permission check) |
| POST | `/api/capture/stop` | Key | Stop live capture |
| GET | `/api/capture/status` | No | Capture engine state |
| POST | `/api/baseline/collect` | Key | Begin baseline collection (backend-owned timer) |
| POST | `/api/baseline/finish` | Key | Manually train baseline |
| GET | `/api/baseline/status` | No | Baseline status + time remaining |
| GET | `/api/baseline/summary` | No | Per-feature baseline mean/std |
| GET | `/api/detection/stats` | No | Live IF detection metrics |
| GET | `/api/report/csv` | No | Export detection report as CSV |
| POST | `/api/replay/start` | Key | Start PCAP replay scenario |
| POST | `/api/replay/stop` | Key | Stop replay |
| GET | `/api/replay/status` | No | Replay state + per-stage latency |
| GET | `/api/replay/baseline-summary` | No | Replay-specific baseline summary |
| GET | `/api/simulate` | No | Test-set simulation events |
| WS | `/ws/live` | No | Live flow event stream |

Endpoints marked **Key** require `X-API-Key` header. Interactive docs at `/docs` (Swagger).

## Tech Stack

| Layer | Technology |
|---|---|
| Frontend | Next.js 14, React, Tailwind CSS |
| Backend | FastAPI, Python 3.11, Uvicorn |
| Capture | Scapy (raw packet sniffing) |
| ML | Isolation Forest, LOF, OCSVM, PCA, Z-score (sklearn), XGBoost |
| Evaluation | 5 unsupervised baselines + supervised ceiling on UNSW-NB15, CIC-IDS-2018 |
| Replay | PCAP-based deterministic demo with per-stage latency instrumentation |
| CI | GitHub Actions (ruff + pytest + next lint + jest) |
| Infra | Docker, Docker Compose, Makefile |

## Deployment (AWS EC2)

1. Launch Ubuntu EC2. Open ports 3000 (dashboard) and 8000 (API).
2. Install Docker and Docker Compose.
3. Clone and deploy:

```bash
git clone https://github.com/your-username/nids-platform.git
cd nids-platform
chmod +x deploy.sh && ./deploy.sh
```

The script generates an API key, sets `NIDS_MODE=production`, and starts both containers with host networking. Backend sniffs the host NIC directly.

- Dashboard: `http://<EC2_PUBLIC_IP>:3000`
- API: `http://<EC2_PUBLIC_IP>:8000`
- Docs: `http://<EC2_PUBLIC_IP>:8000/docs`

Production mode requires explicit `NIDS_API_KEY` and `CORS_ORIGINS` (no defaults). See [`.env.production.example`](.env.production.example).

## Limitations and Future Work

**Current limitations:**
- 13 host-level features (hot, num_failed_logins, logged_in, etc.) are excluded because they require application-layer inspection not available from packet headers
- Supplementary XGBoost classifier is optional and currently disabled unless pre-trained artifacts are present
- Anomaly scores are not calibrated probabilities — post-hoc score comparison between models is approximate
- Single-interface capture only
- LOF and OCSVM subsample training data for tractability on large datasets

**Future work:**
- Generate live-compatible training data via PCAP replay for the supplementary classifier
- Autoencoder baseline for neural anomaly detection comparison
- Multi-interface capture support
- Temporal drift detection across baseline windows

## Resume Bullets

- Built a real-time network anomaly detection platform that captures live traffic, extracts 28 packet-observable features, and scores flows against a user-trained Isolation Forest baseline
- Benchmarked 5 unsupervised anomaly detection methods (Z-score, IF, LOF, OCSVM, PCA) against a supervised XGBoost ceiling on UNSW-NB15 and CIC-IDS-2018, with PR-AUC, recall@FPR, false positives per 10k flows, and per-attack breakdown
- Designed a shared packet-ingestion seam supporting both live Scapy capture and deterministic PCAP replay with per-stage latency instrumentation (parse/features/score/classify/publish)
- Implemented thread-safe flow aggregation, backend-owned baseline timer, server-side API proxy (no secrets in client bundle), and strict production startup validation
- Built an analyst dashboard with real-time WebSocket feed, alert drilldown showing top deviating features vs baseline, and PCAP replay controls — all without requiring root access
- Set up CI pipeline (ruff, pytest, ESLint, Jest), Makefile automation, Docker deployment with non-root containers and `setcap` capture capabilities

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
