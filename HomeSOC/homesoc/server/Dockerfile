FROM python:3.12-slim

WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY rules ./rules
COPY static ./static

ENV HOMESOC_DB=/data/homesoc.db \
    HOMESOC_RULES=/srv/rules

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
