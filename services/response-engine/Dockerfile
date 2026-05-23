FROM python:3.11-slim

WORKDIR /app

# iptables for the blocklist playbook (8B)
RUN apt-get update && \
    apt-get install -y --no-install-recommends iptables iproute2 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "-u", "engine.py"]
