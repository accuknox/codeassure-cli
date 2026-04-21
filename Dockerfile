FROM python:3.12-slim

# Install uv and git
RUN pip install --no-cache-dir uv && apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 codeassureuser

WORKDIR /app

# Install codeassure
RUN uv pip install --system --no-cache git+https://github.com/accuknox/codeassure-cli.git@v0.1.1

# Set ownership
RUN chown -R codeassureuser:codeassureuser /app

USER codeassureuser

WORKDIR /workspace

ENTRYPOINT ["codeassure", "--config", "/app/codeassure.json"]
