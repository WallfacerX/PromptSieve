FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY pyproject.toml README.md LICENSE requirements-dev.lock ./
COPY src ./src
RUN pip install --no-cache-dir -c requirements-dev.lock . \
    && useradd --create-home --uid 10001 promptsieve
USER promptsieve
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=3s CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/healthz', timeout=2)"]
CMD ["uvicorn", "promptsieve.app:create_app", "--factory", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
