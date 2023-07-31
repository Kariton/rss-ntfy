FROM python:3.11-alpine

RUN mkdir -p /rss-ntfy /etc/rss-ntfy
WORKDIR /rss-ntfy

ADD ./rss-ntfy/* /rss-ntfy/
COPY requirements.txt /rss-ntfy/

RUN pip install --no-cache-dir --upgrade pip
RUN pip install --no-cache-dir -r requirements.txt

ENV PYTHONUNBUFFERED=1

CMD ["python", "-u", "/rss-ntfy/rss-ntfy.py"]
