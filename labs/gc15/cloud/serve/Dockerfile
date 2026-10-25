# GC15 guided build: a small CPU-only serving container for Agent Platform (formerly Vertex AI) custom containers.
# It follows Google's custom container contract: listen on 0.0.0.0:$AIP_HTTP_PORT, answer GET $AIP_HEALTH_ROUTE and
# POST $AIP_PREDICT_ROUTE, and read the model from $AIP_STORAGE_URI (the copy Agent Platform made at upload).
# It downloads nothing from the internet at start, so it works inside a VPC Service Controls perimeter.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 HF_HUB_OFFLINE=1 TRANSFORMERS_OFFLINE=1 \
    HF_HUB_DISABLE_TELEMETRY=1
RUN useradd --create-home --uid 10001 server
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --index-url https://download.pytorch.org/whl/cpu torch==2.6.0 \
 && pip install --no-cache-dir -r requirements.txt
COPY server.py .
USER server
EXPOSE 8080
CMD ["python", "server.py"]
