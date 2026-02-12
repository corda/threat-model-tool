FROM mcr.microsoft.com/devcontainers/python:3.12

# Layer 1: System deps (rarely changes — cached long-term)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Layer 2: Python dependencies
COPY requirements-dev.txt /tmp/
COPY src/r3threatmodeling/requirements.txt /tmp/app-requirements.txt

# Install dependencies using uv for speed
# We filter out the local git dependency tree-node because it will be installed as editable in postCreateCommand
RUN sed '/^tree-node @/d' /tmp/app-requirements.txt > /tmp/app-requirements-filtered.txt \
    && uv pip install --system --no-cache -r /tmp/app-requirements-filtered.txt \
    && uv pip install --system --no-cache \
        pytest>=7.0.0 pytest-cov black flake8 mypy pre-commit \
        sphinx sphinx-rtd-theme \
        build twine wheel debugpy \
    && rm -rf /tmp/*.txt

# Layer 3: Editable installs (run after workspace is mounted)
# These must be postCreateCommand because they need the source code
