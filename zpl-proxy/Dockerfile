FROM python:3.11-slim

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir -e .

COPY src/ src/
COPY config/ config/

RUN mkdir -p data certs

# mitmproxy stores its CA cert here; mount ./certs to persist across restarts
ENV MITMPROXY_HOME=/app/certs

EXPOSE 8080

CMD ["mitmdump", \
     "--listen-host", "0.0.0.0", \
     "--listen-port", "8080", \
     "--set", "confdir=/app/certs", \
     "-s", "src/zpl_proxy/addon.py"]
