FROM python:3.15.2-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# non-root user, fixed UID / GID (build args), so the ownership of volumes is the same in all builds
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --system --gid "${APP_GID}" reveal \
    && useradd --system --uid "${APP_UID}" --gid reveal --no-create-home --home-dir /app --shell /usr/sbin/nologin reveal

RUN mkdir /app && mkdir /app/reveal

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip && pip install --requirement requirements.txt

COPY /reveal reveal

# the application files stay owned by root (read-only for the application user), the API does not write files
USER reveal
