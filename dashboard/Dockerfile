FROM python:3.12-slim

WORKDIR /app

# install runtime dependencies first so unrelated source edits don't bust the layer cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app.py db.py filters.py ./
COPY templates ./templates
COPY static ./static

EXPOSE 5000

# gunicorn with two workers covers the small read-only api load comfortably
ENTRYPOINT ["gunicorn", "-w", "2", "-k", "gthread", "--threads", "4", "-b", "0.0.0.0:5000", "--access-logfile", "-", "app:app"]
