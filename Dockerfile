FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY cronometer_mcp ./cronometer_mcp

RUN pip install --no-cache-dir .

ENV PYTHONUNBUFFERED=1
EXPOSE 3000

CMD ["cronometer-mcp-http"]
