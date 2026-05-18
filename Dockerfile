FROM python:3.11-slim

# OWASP Section 6: Run as non-root user
RUN groupadd -r socframework && useradd -r -g socframework socframework

WORKDIR /app

# Install dependencies before copying source (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source
COPY . .

# OWASP Section 6: Drop unnecessary permissions
RUN chown -R socframework:socframework /app

# Memory data directory with correct permissions
RUN mkdir -p /app/memory_data && chown socframework:socframework /app/memory_data

USER socframework

# Secrets come from environment — never baked into image
# OWASP Section 6: Never store secrets in environment variables in Dockerfile
# Use docker-compose secrets or a mounted .env file with restricted permissions

CMD ["python", "main.py"]
