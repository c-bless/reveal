FROM python:3.15.2-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# non-root user, fixed UID / GID (build args), so the ownership of volumes is the same in all builds
ARG APP_UID=10001
ARG APP_GID=10001
RUN groupadd --system --gid "${APP_GID}" reveal \
    && useradd --system --uid "${APP_UID}" --gid reveal --no-create-home --home-dir /app --shell /usr/sbin/nologin reveal

RUN mkdir /app

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip && pip install --requirement requirements.txt

COPY /reveal /app/reveal
COPY /update-data /app/update-data
COPY /uploads /app/uploads
COPY /reports /app/reports
COPY /static /app/static
COPY /configreview_checks /app/configreview_checks

# The application files stay owned by root (read-only for the application user). Only the upload directory is
# writable: a new named volume (upload_volume) takes over the ownership of this directory.
RUN chown reveal:reveal /app/uploads

USER reveal
