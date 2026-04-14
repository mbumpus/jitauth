FROM python:3.12-slim

WORKDIR /app

# Install system deps for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install package
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir ".[postgres]"

# Copy default policies and examples
COPY policies/ policies/
COPY examples/adapters.yaml adapters.yaml

EXPOSE 8700

# Init DB tables and start the broker
CMD ["sh", "-c", "jitauth init-db && jitauth serve --host 0.0.0.0 --port 8700"]
