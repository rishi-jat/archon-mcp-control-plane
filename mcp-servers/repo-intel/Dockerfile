FROM python:3.12-alpine

RUN apk add --no-cache tini

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN addgroup -g 1000 mcp && adduser -u 1000 -G mcp -D mcp
USER mcp

ENV PYTHONUNBUFFERED=1
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["python", "server.py"]
