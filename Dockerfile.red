FROM python:3.11-alpine

# Security hardening: Create non-root user and group
RUN addgroup -g 1001 redgroup && \
    adduser -u 1001 -G redgroup -s /bin/sh -D reduser

WORKDIR /app

# Copy worker application
COPY workers/worker.py /app/workers/worker.py

# Switch to non-root user
USER 1001:1001

ENV ROLE="red-worker"
ENV PORT=8080
ENV PYTHONUNBUFFERED=1

EXPOSE 8080

ENTRYPOINT ["python3", "-u", "/app/workers/worker.py"]
