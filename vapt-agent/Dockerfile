FROM python:3.12-slim

# Scanners: nmap from Debian, nikto from upstream (perl). git is only needed at build time.
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap perl libnet-ssleay-perl libio-socket-ssl-perl libjson-perl libxml-writer-perl git ca-certificates \
    && git clone --depth 1 https://github.com/sullo/nikto /opt/nikto \
    && printf '#!/bin/sh\ncd /opt/nikto/program && exec perl ./nikto.pl "$@"\n' > /usr/local/bin/nikto \
    && chmod +x /usr/local/bin/nikto \
    && apt-get purge -y git && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt msgpack
COPY vapt_agent ./vapt_agent
COPY config ./config
COPY tests ./tests
COPY scripts ./scripts

ENV VAPT_HOST=0.0.0.0 VAPT_PORT=8080 PYTHONUNBUFFERED=1
EXPOSE 8080
CMD ["python", "-m", "vapt_agent"]
