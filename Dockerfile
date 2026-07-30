FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Render sets $PORT; default to 8090 for local docker run
ENV PORT=8090
EXPOSE 8090

CMD ["sh", "-c", "uvicorn server:app --host 0.0.0.0 --port ${PORT}"]
