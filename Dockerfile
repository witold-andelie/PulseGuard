FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PORT=8000 \
    PG_MODE=replay \
    PG_DB_PATH=/tmp/pulseguard.sqlite

WORKDIR /app
COPY pyproject.toml README.md ./
COPY pulseguard ./pulseguard
COPY contracts ./contracts
COPY replay ./replay
COPY web ./web
COPY demo_target ./demo_target
RUN pip install --no-cache-dir ".[scan,stretch]" "flask>=3.0" "pytest>=8" \
    && python -m bandit --version \
    && useradd --create-home --uid 10001 pulseguard
USER pulseguard
EXPOSE 8000
CMD ["sh", "-c", "exec uvicorn pulseguard.api:create_app --factory --host 0.0.0.0 --port \"$PORT\""]
