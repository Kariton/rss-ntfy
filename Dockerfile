### COMPILE ###
FROM python:3.11-alpine AS compile-image

RUN python -m venv /opt/venv
# Make sure we use the virtualenv:
ENV PATH="/opt/venv/bin:$PATH"

COPY requirements.txt .
RUN pip install --upgrade --requirement requirements.txt


### BUILD ###

FROM python:3.11-alpine AS build-image
RUN adduser -D rss-ntfy
USER rss-ntfy
WORKDIR /home/rss-ntfy

ADD --chown=rss-ntfy ./rss-ntfy/ ./rss-ntfy/
COPY --from=compile-image --chown=rss-ntfy /opt/venv /opt/venv

RUN chmod +x ./rss-ntfy/bot.py

# Make sure we use the virtualenv:
ENV PATH="/opt/venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1
CMD ./rss-ntfy/bot.py
