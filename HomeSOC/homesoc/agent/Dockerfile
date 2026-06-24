# Optional Docker image for the HomeSOC agent — LINUX HOSTS ONLY.
#
# A container on Windows or macOS runs inside a Linux VM and CANNOT see the host
# OS's processes, files, sockets, or auth logs. Do NOT use this image there —
# install the native agent with install.ps1 (Windows) or install.sh (macOS).
#
# Even on Linux, the container must run with host visibility:
#
#   docker build -t homesoc-agent ./agent -f ./agent/Dockerfile
#   docker run -d --name homesoc-agent \
#     --pid=host --network=host --privileged \
#     -e HOMESOC_SERVER="http://192.168.1.10:8080" \
#     -e HOMESOC_KEY="changeme" \
#     -v /:/host:ro -v /var/log:/var/log:ro \
#     homesoc-agent
#
# Fidelity is still polling-grade (it reads the host /proc via --pid=host); this
# is a convenience packaging, not a kernel sensor.
FROM python:3.12-slim

WORKDIR /opt/agent
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY homesoc_agent.py .

CMD ["python", "homesoc_agent.py", "--no-prompt"]
