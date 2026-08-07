FROM python:3.11-slim

WORKDIR /app

# git for compose backups, openssh-client + rsync for remote deploys/migrations
RUN apt-get update && apt-get install -y --no-install-recommends git openssh-client rsync && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p /app/data

EXPOSE 5000

# Run the main registry app via Gunicorn (production WSGI server)
# Use gthread worker class to support Flask's threading model with multiple workers
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8", "--worker-class", "gthread", "--timeout", "300", "--keep-alive", "5", "--access-logfile", "-", "--error-logfile", "-", "locator:app"]
