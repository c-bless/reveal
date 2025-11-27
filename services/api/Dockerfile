FROM python:3.14.0-bookworm

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN mkdir /app && mkdir /app/reveal

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip && pip install --requirement requirements.txt

COPY /reveal reveal


