# ── Build stage ──────────────────────────────────────────────────────
FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install OS-level dependencies + libcap2-bin for setcap
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc libgomp1 libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# ── Dependencies ─────────────────────────────────────────────────────
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ── Application code ─────────────────────────────────────────────────
COPY . .

# ── Non-root user with capture capability ────────────────────────────
# setcap grants the Python interpreter packet-capture rights so the
# container does not need to run as root.  cap_add in docker-compose
# is still required to allow the kernel to honour the capability.
RUN groupadd --system nids \
    && useradd --system --gid nids --create-home nids \
    && setcap cap_net_raw,cap_net_admin+eip $(readlink -f $(which python3))

USER nids

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
