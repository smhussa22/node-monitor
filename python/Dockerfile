FROM python:3.12-slim

WORKDIR /app

# only runtime dep is requests for the http push side
RUN pip install --no-cache-dir requests==2.32.3

COPY simulators/ ./simulators/
COPY drive_collector.py .

# default args produce a steady stream of mixed-vendor metrics; deployments override these
ENTRYPOINT ["python3", "-u", "drive_collector.py"]
CMD ["--count", "100", "--interval", "30", "--duration", "0", "--collector", "http://collector:8000", "--netflow-host", "collector", "--netflow-port", "2055"]
