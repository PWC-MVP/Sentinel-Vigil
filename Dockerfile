# ── Stage 1: Build React/Vite frontend ────────────────────────────────────────
FROM node:20-alpine AS frontend-build
WORKDIR /build/frontend
COPY frontend/package*.json ./
RUN npm ci --silent
COPY frontend/ ./
RUN npm run build

# ── Stage 2: Python backend + bundled frontend ────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Install Python dependencies
COPY backend/requirements.txt ./backend/requirements.txt
RUN pip install --no-cache-dir -r backend/requirements.txt

# Copy backend source
COPY backend/ ./backend/

# Root-level modules imported by the backend
COPY investigator.py report_generator.py enrich_ips.py \
     generate_mitre_coverage_report.py generate_mitre_heatmap.py ./

# Copy built frontend static files from Stage 1
COPY --from=frontend-build /build/frontend/dist ./frontend/dist

# Writable dirs for reports and temp files
RUN mkdir -p reports tmp

EXPOSE 8000

CMD ["uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
