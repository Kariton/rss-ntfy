#!/usr/bin/env python3

import os
import re
import yaml
import requests
import feedparser
import base64
import time
import random
import logging
import json
import threading
import copy
import jsonschema
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from croniter import croniter
from markdownify import markdownify as md
from pathlib import Path


CONFIG = dict()
DEFAULT_CONFIG = dict()
last_modification_time = 0

logger = None


def merge_configurations(base_config, custom_config):
    for key, value in custom_config.items():
        if isinstance(value, dict):
            if key in base_config and isinstance(base_config[key], dict):
                base_config[key] = merge_configurations(base_config[key], value)
            else:
                base_config[key] = value
        elif value is None:
            base_config.pop(key, None)
        else:
            base_config[key] = value
    return base_config


def custom_validation(config):
    feeds_keys = config.get("feeds", {}).keys()
    services_keys = config.get("services", {}).keys()

    for feed_key in feeds_keys:
        if feed_key not in services_keys:
            raise jsonschema.exceptions.ValidationError(
                f"For each 'feeds' entry with key '{feed_key}', there must be a corresponding 'services' entry with the same key."
            )

    if "ntfy_topic" in config["global"]:
        return

    for feed_name, feed_config in config["feeds"].items():
        if not "ntfy_topic" in feed_config:
            if not "ntfy_topic" in config["services"][feed_name] and not "ntfy_topic" in config["global"]:
                raise jsonschema.ValidationError("The property 'ntfy_topic' must be present in either 'global', 'feeds', or 'services'.")


def load_config(file_path):
    try:
        with open(file_path, 'r') as file:
            return yaml.safe_load(file)
    except FileNotFoundError:
        logger.error("Config file not found.")
        return None
    except yaml.YAMLError as e:
        logger.error(f"Error loading the config file '{file_path}': {e}")
        return None


def load_schema(schema_path):
    with open(schema_path, 'r') as schema_file:
        return json.load(schema_file)


def update_config(init=False):
    global CONFIG, DEFAULT_CONFIG

    config_path = "/etc/rss-ntfy/config.yml"
    schema_path = "./rss-ntfy/schema.json"
    try:
        custom_config = load_config(config_path)

        if custom_config is not None:
            if logger is not None:
                logger.debug(f'custom_config": {json.dumps(custom_config)}')
                logger.debug(f'default_config": {json.dumps(CONFIG)}')

            merged_config = merge_configurations(copy.deepcopy(DEFAULT_CONFIG), custom_config)

            if logger is not None:
                logger.debug(f'merged_config": {json.dumps(merged_config)}')

            json_schema = load_schema(schema_path)

            try:
                jsonschema.validate(merged_config, json_schema)
                custom_validation(merged_config)
                if logger is not None:
                    logger.info("Config is valid.")
                else:
                    print(f"Config is valid.")

            except jsonschema.exceptions.ValidationError as e:
                if logger is not None:
                    logger.error(f"Config validation failed: {e}")
                    return
                else:
                    print(f"Config validation failed: {e}")
                    return

            if not init:
              compare_config(CONFIG, merged_config)

            CONFIG = merged_config

            if logger is not None:
                logger.debug(f'"CONFIG": {json.dumps(CONFIG)}')

        else:
            return

    except FileNotFoundError:
        logger.error("Config file not found.")

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")


def init_config():
    global CONFIG, DEFAULT_CONFIG

    default_config = "./rss-ntfy/default.yml"

    defaults = load_config(default_config)
    DEFAULT_CONFIG = defaults
    CONFIG = copy.deepcopy(DEFAULT_CONFIG)

    update_config(init=True)

    config_thread = threading.Thread(target=watch_config)
    config_thread.start()


def compare_config(running, update):
    logger.debug(f"\n\n{running}\n\n{update}\n\n")
    if running != update:
        logger.info("Reloading...")
    if update['config']['cache_location'] != running['config']['cache_location']:
        logger.warning("Cache location has changed. Please restart for the changes to take effect.")
    if update['config']['log_level'] != running['config']['log_level']:
        logger.warning("Log level has changed. Please restart for the changes to take effect.")
    if update['config']['schedule'] != running['config']['schedule']:
        logger.warning("Schedule has changed. Please restart for the changes to take effect.")


def watch_config():
    global CONFIG

    config_path = "/etc/rss-ntfy/"

    event_handler = ConfigFileHandler()
    observer = Observer()
    observer.schedule(event_handler, path=config_path, recursive=False)
    observer.start()

    try:
        while True:
            threading.Event().wait(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()


class ConfigFileHandler(FileSystemEventHandler):
    def on_modified(self, event):
        global CONFIG

        config_path = "/etc/rss-ntfy/config.yml"

        global last_modification_time

        if event.src_path.endswith(config_path):
            current_modification_time = os.path.getmtime(event.src_path)
            logger.info("Configuration changed...")
            if current_modification_time != last_modification_time:
                last_modification_time = current_modification_time
                update_config()


def init_logger():
    global logger

    config = CONFIG['config']
    log_level = config.get('log_level').upper()

    log_format = '[%(levelname)s] %(asctime)s - %(name)s - %(message)s'

    logger = logging.getLogger(__name__)
    logger.setLevel(log_level)

    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)

    formatter = logging.Formatter(log_format)
    console_handler.setFormatter(formatter)

    logger.addHandler(console_handler)


def split_message_into_parts(data_json, max_size):
    message = data_json['ntfy_message']
    lines = message.splitlines()

    parts = []
    current_part = ""
    current_title = data_json['ntfy_title']

    for line in lines:
        words = line.split()
        for word in words:
            if len(current_part) + len(word) + 1 <= max_size:
                current_part += word + " "
            else:
                parts.append((current_title, current_part.strip()))
                current_part = word + " "
                current_title = data_json['ntfy_title']

        current_part += "\n"

    if current_part:
        parts.append((current_title, current_part.strip()))

    return parts


def ntfy_headers(ntfy_auth, ntfy_cache=None, ntfy_icon=None, ntfy_tags=None, ntfy_priority=None, ntfy_email=None, ntfy_call=None, ntfy_delay=None, ntfy_thumbnail=None):
    headers = {
        'Content-Type': 'application/json',
        'charset': 'utf-8',
        'X-Markdown': 'True',
    }

    if ntfy_auth is not None:
        if ntfy_auth['username'] is not None and ntfy_auth['password'] is not None:
            headers['Authorization'] = "Basic " + base64.b64encode((auth['username'] + ":" + ntfy_auth['password']).encode()).decode()

        if ntfy_auth['token'] is not None:
            headers['Authorization'] = f"Bearer {auth['token']}"

    if ntfy_icon is not None:
        headers['X-Icon'] = ntfy_icon

    if ntfy_tags is not None:
        headers['X-Tags'] = ','.join(ntfy_tags)

    if ntfy_thumbnail is not None:
        headers['X-Attach'] = ntfy_thumbnail

    if ntfy_priority is not None:
        headers['X-Priority'] = ntfy_priority

    if ntfy_cache is not None:
        headers['X-Cache'] = ntfy_cache

    if ntfy_email is not None:
        headers['X-Email'] = ntfy_email

    if ntfy_call is not None:
        headers['X-Call'] = ntfy_call

    if ntfy_delay is not None:
        headers['X-Delay'] = ntfy_delay

    return headers


def ntfyr(data_json):
    config = CONFIG['config']
    global_config = CONFIG['global']

    max_message_size = int(config.get('max_message_size'))
    max_attempts = int(config.get('max_attempts'))
    retry_wait = int(config.get('retry_wait'))

    attempts = 0

    request_json = {
        "topic": data_json['ntfy_topic'],
    }

    headers = ntfy_headers(data_json['ntfy_auth'], data_json['ntfy_cache'], data_json['ntfy_icon'], data_json['ntfy_tags'], data_json['ntfy_priority'], data_json['ntfy_email'], data_json['ntfy_call'], data_json['ntfy_delay'], data_json['ntfy_thumbnail'])

    parts = split_message_into_parts(data_json, max_message_size)
    total_parts = len(parts)

    if data_json['item_link'] is not None:
        request_json['actions'] = [
            {
                "action": "view",
                "label": "View!",
                "url": data_json['item_link']
            }
        ]

    for part_num, (part_title, part_message) in enumerate(reversed(parts), start=1):
        if total_parts > 1:
            part_title = f"{part_title} [{total_parts - part_num + 1}/{total_parts}]"

        request_json["title"] = part_title
        request_json["message"] = part_message

        if data_json['item_link'] is not None:
            request_json['actions'] = [
                {
                    "action": "view",
                    "label": "View!",
                    "url": data_json['item_link']
                }
            ]
    
        while attempts < max_attempts:
            logger.info(f"sending message (part {part_num} of {total_parts})...")
            logger.debug(f'"post_data": {json.dumps(request_json)}')
            logger.debug(f'"post_header": {json.dumps(headers)}')
            try:
                response = requests.post(data_json['ntfy_server'], headers=headers, json=request_json)
                logger.info(f"successfully sent part {part_num}!")
                try:
                    response_json = response.json()
                    logger.debug(f'"response_content": {json.dumps(response_json)}')
                except json.JSONDecodeError:
                    logger.debug(f'"response_content": "{response.text}"')
                response.raise_for_status()
                break
            except requests.exceptions.HTTPError as e:
                logger.error(e)
                logger.error(f'"post_data": {json.dumps(request_json)}')
                logger.error(f'"post_header": {json.dumps(headers)}')
                try:
                    response_json = response.json()
                    logger.error(f'"response_content": {json.dumps(response_json)}')
                except json.JSONDecodeError:
                    logger.error(f'"response_content": "{response.text}"')
    
                if response.status_code == 429:
                    logger.warning(f"Retry in {retry_wait} seconds...")
                    time.sleep(retry_wait)
                else:
                    raise StopIteration
            attempts += 1
        else:
            logger.error(f"Failed to send part {part_num} of {total_parts} after {max_attempts} attempts.")
            logger.error(f'"post_data": {json.dumps(request_json)}')
            logger.error(f'"post_header": {json.dumps(headers)}')
            try:
                response_json = response.json()
                logger.error(f'"response_content": {json.dumps(response_json)}')
            except json.JSONDecodeError:
                logger.error(f'"response_content": "{response.text}"')
            raise StopIteration

        if total_parts > 1:
            time.sleep(2)


def handlebar_replace(string, replacement):
    return re.sub('{{.*}}', replacement, string)


def build_message(item):
    message = str()

    if 'sub_title' in item:
        message += f"{item.sub_title}\n"
    elif 'published' in item:
        message += f"Published: {item.published}\n"
    elif 'updated' in item:
        message += f"Updated: {item.updated}\n"

    if 'media_statistics' in item:
        message += f"Media statistics:\n"
        for k, v in item.media_statistics.items():
            message += f"    {k.capitalize()}: {v}\n"

    if 'media_starrating' in item:
        message += f"Media starring:\n"
        for k, v in item.media_starrating.items():
            message += f"    {k.capitalize()}: {v}\n"

    message += "\n"

    if item.description == item.summary:
        message += f"{md(item.summary)}\n"
    else:
        message += f"{md(item.description)}\n\n"
        message += f"{md(item.summary)}\n"

    message = re.sub(r'\n{3,}', '\n\n', message)

    return message


def build_subtitle(item, feed, url, feed_display_name=None, ntfy_subtitle_prefix=None, ntfy_subtitle_seperator=None):
    ntfy_subtitle_text = f"[{feed_display_name or feed}]({url})"
    ntfy_subtitle_postfix = str()
    all_authors = list()

    if 'authors' in item and 'name' in item["authors"]:
        for author in item['authors']:
            author_linked = f"[{author['name']}]({author['href']})" if 'href' in author else author_name
            all_authors.append(author_linked)
        ntfy_subtitle_postfix += f" {', '.join(all_authors)}"
    elif 'author_detail' in item and 'name' in item['author_detail'] and item['author_detail']['name'] != feed:
        author_name = item["author_detail"]["name"]
        author_link = f"[{author_name}]({item['author_detail']['href']})" if 'href' in item["author_detail"] else author_name
        ntfy_subtitle_postfix += f" {author_link}"
    elif 'author_detail' in item and 'email' in item['author_detail'] and item['author_detail']['email'] != feed:
        author_name = item["author_detail"]["email"]
        author_link = f"[{author_name}]({item['author_detail']['email']})" if 'href' in item["author_detail"] else author_name
        ntfy_subtitle_postfix += f" {author_link}"
    elif 'author' in item and item['author'] != feed:
        ntfy_subtitle_postfix += f" {item['author']}"

    subtitle_parts = [part for part in [ntfy_subtitle_prefix, ntfy_subtitle_text, ntfy_subtitle_seperator, ntfy_subtitle_postfix] if part is not None]

    subtitle = " ".join(subtitle_parts)
    subtitle = re.sub(r'^\s+|\s+$|\s+(?=\s)', ' ', subtitle)

    return subtitle


def read_file(file_path):
    try:
        with open(file_path, "r") as file:
            data = json.load(file)
    except (FileNotFoundError, json.JSONDecodeError):
        data = {}

    return data


def write_file(file_path, data):
    with open(file_path, "w") as file:
        json.dump(data, file)


def cleanup_file(file_path, feed, feed_data):
    feed_links = {item.link for item in feed_data.entries}
    data = read_file(file_path)

    remove_links = [link for link in data.get(feed, []) if link not in feed_links]
    data[feed] = [link for link in data.get(feed, []) if link not in remove_links]

    write_file(file_path, data)


def process_feed(data_json):
    config = CONFIG['config']

    ntfy_server = data_json['ntfy_server']
    ntfy_topic = data_json['ntfy_topic']
    feed = data_json['feed']
    feed_url = data_json['feed_url']
    url = data_json['url']

    feed_display_name = data_json['feed_display_name']
    ntfy_subtitle_prefix = data_json['ntfy_subtitle_prefix']
    ntfy_subtitle_seperator = data_json['ntfy_subtitle_seperator']
    service_hist = data_json['service_hist']
    service = data_json['service']

    logger.info(f"feed_url: {feed_url}")

    feed_data = feedparser.parse(feed_url)
    item_count = 1
    total_items = len(feed_data.entries)

    if feed_data.status != 200:
      logger.error(f"Feed unavailable: {service} - {feed} - {feed_url} - {ntfy_server}/{ntfy_topic}
      return

    for item in feed_data.entries:
        feed_wait = int(config.get('feed_wait'))
        
        ntfy_thumbnail = None

        logger.info(f"[{item_count}/{total_items}] {service} - {feed} - {feed_url} - {ntfy_server}/{ntfy_topic}")

        logger.debug(f'"feed_item": {json.dumps(item)}')

        message = build_message(item)
        subtitle = build_subtitle(item, feed, url, feed_display_name, ntfy_subtitle_prefix, ntfy_subtitle_seperator)
        ntfy_title = item.title
        ntfy_message = f"{subtitle}\n\n{message}"

        data_json['ntfy_title'] = item.title
        data_json['ntfy_message'] = f"{subtitle}\n\n{message}"
        data_json['ntfy_thumbnail'] = ntfy_thumbnail
        data_json['item_link'] = item.link

        if 'media_thumbnail' in item:
            if 'url' in item['media_thumbnail'][0]:
                data_json['ntfy_thumbnail'] = item['media_thumbnail'][0]['url']


        hist_json = read_file(service_hist)

        if item.link not in hist_json.get(feed, []):
            try:
                ntfyr(data_json)
                time.sleep(feed_wait)
            except StopIteration:
                break

            hist_json.setdefault(feed, []).append(item.link)
            write_file(service_hist, hist_json)
        else:
            logger.info(f"already sent.")

        item_count += 1
    cleanup_file(service_hist, feed, feed_data)


def main():
    config = CONFIG['config']
    global_config = CONFIG['global']

    service_wait = int(config.get('service_wait'))

    cache_path = config.get('cache_location')
    cache_location = os.path.expanduser(cache_path)

    Path(f"{cache_location}/").mkdir(parents=True, exist_ok=True)

    for service_name, service_config in CONFIG['services'].items():
        logger.info(f"service: {service_name}")
        logger.debug(f'"service_config": {json.dumps(service_config)}')

        service_hist = f"{cache_location}/{service_name}_hist"
        Path(service_hist).touch(exist_ok=True)

        for feed_config in CONFIG['feeds'][service_name]:
            if not isinstance(feed_config, dict):
                feed = feed_config
                feed_config = {}
            else:
                feed = feed_config['name']
            logger.info(f"feed: {feed}")
            logger.debug(f'"feed_config": {json.dumps(feed_config)}')

            feed_url = handlebar_replace(service_config['service_feed'], feed)
            url = handlebar_replace(service_config['service_url'], feed)

            data_json = {
                'service': service_name,
                'feed': feed,
                'feed_url': feed_url,
                'url': url,
                'service_hist': service_hist,
                'feed_display_name': feed_config.get('feed_display_name', service_config.get('feed_display_name', global_config.get('feed_display_name'))),
                'ntfy_server': feed_config.get('ntfy_server', service_config.get('ntfy_server', global_config.get('ntfy_server'))),
                'ntfy_topic': feed_config.get('ntfy_topic', service_config.get('ntfy_topic', global_config.get('ntfy_topic'))),
                'ntfy_auth': feed_config.get('ntfy_auth', service_config.get('ntfy_auth', global_config.get('ntfy_auth'))),
                'ntfy_subtitle_prefix': feed_config.get('ntfy_subtitle_prefix', service_config.get('ntfy_subtitle_prefix', global_config.get('ntfy_subtitle_prefix'))),
                'ntfy_subtitle_seperator': feed_config.get('ntfy_subtitle_seperator', service_config.get('ntfy_subtitle_seperator', global_config.get('ntfy_subtitle_seperator'))),
                'ntfy_icon': feed_config.get('ntfy_icon', service_config.get('ntfy_icon', global_config.get('ntfy_icon'))),
                'ntfy_tags': feed_config.get('ntfy_tags', service_config.get('ntfy_tags', global_config.get('ntfy_tags'))),
                'ntfy_priority': feed_config.get('ntfy_priority', service_config.get('ntfy_priority', global_config.get('ntfy_priority'))),
                'ntfy_cache': feed_config.get('ntfy_cache', service_config.get('ntfy_cache', global_config.get('ntfy_cache'))),
                'ntfy_email': feed_config.get('ntfy_email', service_config.get('ntfy_email', global_config.get('ntfy_email'))),
                'ntfy_call': feed_config.get('ntfy_call', service_config.get('ntfy_call', global_config.get('ntfy_call'))),
                'ntfy_delay': feed_config.get('ntfy_delay', service_config.get('ntfy_delay', global_config.get('ntfy_delay')))
            }

            logger.debug(f"data_json: {json.dumps(data_json)}")

            process_feed(data_json)
            time.sleep(service_wait)


def parse_cron_definition(cron_definition):
    minute, hour, day, month, day_of_week = cron_definition.split()
    return f"{minute} {hour} {day} {month} {day_of_week}"


def init_schedule():
    global CONFIG

    config = CONFIG['config']

    schedule = config.get('schedule')

    cron_expression = parse_cron_definition(schedule)
    cron = croniter(cron_expression)

    while True:
        next_run_time = cron.get_next(float)
        next_run_readable = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(next_run_time))
        sleep_time = next_run_time - time.time()

        logger.info(f"next run: {next_run_readable}")
        if sleep_time > 0:
            time.sleep(sleep_time)
            main()


if __name__ == '__main__':
    init_config()
    print(f'"CONFIG": {json.dumps(CONFIG, indent=4)}')

    init_logger()

    config = CONFIG['config']

    log_level = config.get('log_level').upper()
    service_wait = int(config.get('service_wait'))
    feed_wait = int(config.get('feed_wait'))
    schedule = config.get('schedule')

    logger.info(f"log level: {log_level}")
    logger.info(f"service wait: {service_wait}")
    logger.info(f"feed wait: {feed_wait}")
    logger.info(f"schedule: {schedule}")
    logger.info("started rss-ntfy!")

    if bool(CONFIG['config']['run_on_startup']):
        logger.info("running on startup.")
        main()
 
    init_schedule()

