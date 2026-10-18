FROM python:3.12-slim

# Install uv and git
RUN pip install --no-cache-dir uv && apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 codeassureuser

WORKDIR /app

# Build from the parent directory containing both source checkouts:
# docker build -f codeassure-cli/Dockerfile -t accuknox/codeassure:local .
COPY code-context-graph/pyproject.toml code-context-graph/README.md /opt/code-context-graph/
COPY code-context-graph/context_graph /opt/code-context-graph/context_graph
COPY codeassure-cli/pyproject.toml codeassure-cli/README.md /opt/codeassure-cli/
COPY codeassure-cli/sast_verify /opt/codeassure-cli/sast_verify
RUN uv pip install --system --no-cache /opt/code-context-graph /opt/codeassure-cli

# Set ownership
RUN chown -R codeassureuser:codeassureuser /app

USER codeassureuser

WORKDIR /workspace

ENTRYPOINT ["codeassure"]
