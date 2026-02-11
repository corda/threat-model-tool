FROM mcr.microsoft.com/devcontainers/python:3.12

# Layer 1: System deps (rarely changes — cached long-term)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install uv
RUN pip install uv

# Layer 2: Python dependencies (changes when requirements.txt changes)
# Copy only requirement files first for better layer caching
COPY requirements-dev.txt /tmp/
COPY src/r3threatmodeling/requirements.txt /tmp/app-requirements.txt

# Install deps WITHOUT the git-based tree-node (it's installed as editable from workspace)
RUN sed '/^tree-node @/d' /tmp/app-requirements.txt > /tmp/app-requirements-filtered.txt \
    && pip install --no-cache-dir -r /tmp/app-requirements-filtered.txt \
    && pip install --no-cache-dir \
        pytest>=7.0.0 pytest-cov black flake8 mypy pre-commit \
        sphinx sphinx-rtd-theme \
        build twine wheel debugpy \
    && rm -rf /tmp/*.txt

# Layer 3: Editable installs (run after workspace is mounted)
# These must be postCreateCommand because they need the source code
