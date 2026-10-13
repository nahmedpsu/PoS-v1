# Reproducible environment for the PoS simulation.
#   docker build -t pos-sim .
#   docker run --rm pos-sim pytest -q
#   docker run --rm -v "$PWD/out:/out" pos-sim python -m pop_sim run-v2 --quick --out /out/results --figures /out/figures
#   docker build --build-arg WITH_SUMO=1 -t pos-sim-sumo .     # adds Eclipse SUMO and git for the traces
#   docker run --rm -v "$PWD/out:/app/out" pos-sim-sumo scripts/reproduce.sh
FROM python:3.11-slim
ARG WITH_SUMO=0
WORKDIR /app
COPY requirements-dev.txt requirements.lock requirements-sumo.lock pyproject.toml ./
RUN pip install --no-cache-dir -r requirements.lock \
 && if [ "$WITH_SUMO" = "1" ]; then \
      pip install --no-cache-dir -r requirements-sumo.lock \
      && apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*; \
    fi
COPY src ./src
COPY tests ./tests
COPY config ./config
COPY scripts ./scripts
ENV PYTHONPATH=/app/src
CMD ["python", "-m", "pop_sim", "demo", "--mobility", "--consensus", "popv2"]
