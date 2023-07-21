FROM python:latest

ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONUNBUFFERED 1

RUN mkdir /app
RUN mkdir /app/systemdb
RUN mkdir /app/reports
RUN mkdir /app/update-data
RUN mkdir /app/uploads

WORKDIR /app

RUN pip install --upgrade pip

COPY requirements.txt .

RUN pip install -r requirements.txt

COPY /systemdb systemdb
COPY /update-data update-data
COPY /uploads uploads
COPY /reports reports


