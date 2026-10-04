# Reproducible environment for the PoS simulation.
#   docker build -t pos-sim .
#   docker run --rm pos-sim pytest -q
#   docker run --rm -v "$PWD/out:/out" pos-sim python -m pop_sim run-v2 --quick --out /out/results --figures /out/figures
FROM python:3.12-slim
WORKDIR /app
COPY requirements-dev.txt requirements.txt pyproject.toml ./
RUN pip install --no-cache-dir -r requirements-dev.txt
COPY src ./src
COPY tests ./tests
COPY config ./config
ENV PYTHONPATH=/app/src
CMD ["python", "-m", "pop_sim", "demo", "--mobility", "--consensus", "popv2"]
