FROM python:3.11-slim 

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /bin/ 

COPY pyproject.toml .
COPY uv.lock . 

COPY . /app 

WORKDIR /app

RUN uv sync --locked 

CMD ["uv", "run", "uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8000"]  