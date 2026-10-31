# Deliberately vulnerable local demo only. Bind the published port to 127.0.0.1.
FROM python:3.12-slim
WORKDIR /demo
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
    && useradd --create-home --uid 10001 demo \
    && chown demo:demo /demo
COPY routes.py .
USER demo
EXPOSE 5001
CMD ["flask", "--app", "routes", "run", "--host", "0.0.0.0", "--port", "5001"]
