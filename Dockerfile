FROM python:3.12-slim

# Install uv
RUN pip install --no-cache-dir uv

# Create non-root user
RUN useradd -m -u 1000 codeassureuser

WORKDIR /app

# Copy project files
COPY pyproject.toml ./
COPY sast_verify/ ./sast_verify/
# COPY codeassure.json ./

# Install the package
RUN uv pip install --system --no-cache .

# Set ownership
RUN chown -R codeassureuser:codeassureuser /app

USER codeassureuser

WORKDIR /workspace

ENTRYPOINT ["codeassure", "--config", "/app/codeassure.json"]
