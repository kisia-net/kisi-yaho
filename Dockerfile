FROM python:3.13-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH"
WORKDIR /app
RUN python -m venv "$VIRTUAL_ENV"
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && pip install --no-cache-dir -r requirements.txt
RUN python -c "from pyvelociraptor import api_pb2, api_pb2_grpc"
RUN groupadd --system hawki && useradd --system --gid hawki --home-dir /app hawki
COPY app.py .
COPY hawki_chat_agent.py .
COPY hawki_alert_analysis ./hawki_alert_analysis
COPY data ./data
COPY templates ./templates
COPY static ./static
RUN chown -R hawki:hawki /app
USER hawki
EXPOSE 5000
# /healthz is the only unauthenticated endpoint. The probe previously called
# /api/build, which requires a session and answers 401, so urlopen raised and
# the container was reported unhealthy while serving normally.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/healthz', timeout=3)"
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--threads", "4", "--timeout", "300", "--access-logfile", "-", "--error-logfile", "-", "app:app"]
