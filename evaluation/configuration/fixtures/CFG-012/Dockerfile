FROM python:3.12
WORKDIR /app
# FROM python:latest
# ADD secret.txt /app/secret.txt
# USER root
COPY . /app
USER appuser
CMD ["python", "app.py"]
