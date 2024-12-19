FROM python:3.11-slim-bookworm
EXPOSE 8000

RUN apt-get update && apt-get upgrade -y && apt-get install -y \
    git \
    && rm -rf /var/lib/apt/lists/*

RUN python3 -m pip install --upgrade pip

WORKDIR /app/opencve
COPY . .
RUN python3 -m pip install -r requirements.txt
CMD ["python3","manage.py", "runserver", "0.0.0.0:8000"]