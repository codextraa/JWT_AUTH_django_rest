FROM python:3.12-slim

# Deps stage: Install Python dependencies
FROM python:3.12-alpine AS deps
WORKDIR /app
COPY requirements.txt ./
RUN apk add --no-cache python3-dev musl-dev linux-headers gcc \
    && pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt \
    && apk del python3-dev musl-dev linux-headers gcc

# Builder stage: Prepare app code
FROM python:3.12-alpine AS builder
WORKDIR /app
COPY --from=deps /usr/local/lib/python3.12/site-packages/ /usr/local/lib/python3.12/site-packages/
COPY --from=deps /usr/local/bin/ /usr/local/bin/
COPY . .

# Runner stage: Final production image
FROM python:3.12-alpine AS runner
WORKDIR /app
COPY ./backend/requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    postgresql-client-17 \
    && curl -1sLf 'https://artifacts-cli.infisical.com/setup.deb.sh' | bash \
    && apt-get install -y infisical \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8000