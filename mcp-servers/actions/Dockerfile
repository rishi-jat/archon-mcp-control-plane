FROM python:3.12-alpine AS base

RUN apk add --no-cache tini

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN adduser -D -u 1000 archon
USER archon

ENTRYPOINT ["tini", "--"]
CMD ["python", "server.py"]
