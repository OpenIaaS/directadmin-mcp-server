FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    MCP_HOST=0.0.0.0 \
    PORT=8888

WORKDIR /app

RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin mcp \
    && mkdir -p /app/logs \
    && chown -R mcp:mcp /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --chown=mcp:mcp . .

USER mcp
EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8888/health')" || exit 1

CMD ["python", "main.py"]
