FROM python:3.12-slim

WORKDIR /app

COPY pyproject.toml ./
COPY sentinel/ sentinel/

RUN pip install --no-cache-dir .

EXPOSE 8000

CMD ["sentinel", "serve", "--host", "0.0.0.0", "--port", "8000"]
