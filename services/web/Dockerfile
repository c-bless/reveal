FROM python:3.12.1-bookworm

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN mkdir /app

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip && pip install --requirement requirements.txt

COPY /reveal /app/reveal
COPY /update-data /app/update-data
COPY /uploads /app/uploads
COPY /reports /app/reports
COPY /static /app/static:python: