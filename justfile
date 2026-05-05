default:
    @just --list

dev:
    uv run uvicorn app.main:app --reload --host 0.0.0.0 --port 8022

lint:
    uv run ruff check .
    uv run ruff format --check .

format:
    uv run ruff check --fix .
    uv run ruff format .

test:
    uv run pytest -v

coverage:
    uv run pytest --cov=app --cov-report=term
