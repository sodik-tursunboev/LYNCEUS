# The page detonator (D1, ADR-025). Built by `python tasks.py detonator` as lynceus-detonator:1.1.0.
# Base: Microsoft's Playwright image, pinned by digest (pulled 2026-11-11). It ships the browsers;
# the Python package is installed here from hash-pinned wheels.
FROM mcr.microsoft.com/playwright/python:v1.64.1-noble@sha256:330d401ae23c905896a0c26c66c36fc971b621519e7b11b435a8328d7bf6e031

COPY requirements.txt /opt/detonator/requirements.txt
RUN pip install --no-cache-dir --break-system-packages --require-hashes --only-binary=:all: \
        -r /opt/detonator/requirements.txt
COPY detonate.py egress.py /opt/detonator/

# Browsers run as the non-root user with Chromium's own sandbox on (Playwright's guidance for
# untrusted sites); the container runs read-only with a tmpfs /tmp, so HOME points there.
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1 PLAYWRIGHT_BROWSERS_PATH=/ms-playwright
USER pwuser
ENTRYPOINT ["/usr/bin/python3", "-I", "/opt/detonator/detonate.py"]
