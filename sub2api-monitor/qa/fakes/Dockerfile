FROM python:3.13-alpine

RUN addgroup -S app && adduser -S -G app app
WORKDIR /app
COPY server.py /app/server.py
USER app
ENTRYPOINT ["python", "/app/server.py"]
