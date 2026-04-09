FROM python:3.12-slim

LABEL maintainer="HuntBox <contact@huntbox.com.br>"
LABEL description="JSHunter — Advanced JavaScript Security Analyzer"

WORKDIR /app

# Install Python dependencies first
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright with all system deps
RUN playwright install --with-deps chromium

# Copy application
COPY . .

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:5000/api/health')" || exit 1

# Run
CMD ["python", "app.py"]
