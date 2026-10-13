FROM python:3.12-slim

WORKDIR /app
COPY src/log_triage.py .

ENV PORT=8080
EXPOSE 8080

CMD ["python3", "log_triage.py"]
