# RSS ntfy

Very small RSS notifier using [ntfy](https://ntfy.sh/).  
Forked from [julianorchard/rss-ntfy](https://github.com/julianorchard/rss-ntfy) and mostly rewritten to add furhter functionality.

I would *highly* recommend using a self hosted ntfy instance, so that you can use whatever ntfy names you want.

Each post from a feed gets send as Markdown text.  
In order to avoid duplicate posts, the "link" extracted from the RSS items is stored in a `_hist` file and  
subsequently deleted once they are no longer present in the feed.  
Some feeds might cause reposts because they re-include "old" listings.

## Usage

### Installation

```sh
pip install -r requirements.txt
mkdir /etc/rss-ntfy/
cp ./config/config.yml /etc/rss-ntfy/config.yml
```

Alternatively, use Docker compose:

```sh
docker compose up
```

This will create a persistent volume for the storage of the `_hist` files, too (at least per default).

### Configuration

The script includes a set of default service definition and configuration which you might want to change.
  
[default.yml](rss-ntfy/default.yml) defines a set of `feeds`, `services`, `global` settings and `config`. **[DONT EDIT]**  
Snippet:
```yaml
---

global:                                                         # settings to use as defaults
  ntfy_server: https://ntfy.sh                                  # server to use if no other is defined on service level
  [...]
  
services: # service definition
  github_release:                                               # service name - referenced within the 'feeds' definition
    service_feed: https://github.com/{{ name }}/releases.atom   # where the rss feed is located
    service_url: https://github.com/{{ name }}                  # used in the sub-title to link to the feed
    ntfy_icon: https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png
    ntfy_subtitle_prefix: 🤖 GitHub Release
    ntfy_subtitle_seperator: by
    ntfy_tags: ['robot']

  github_commit:
    service_feed: https://github.com/{{ name }}/commits.atom
    service_url: https://github.com/{{ name }}
    ntfy_icon: https://github.githubassets.com/images/modules/logos_page/GitHub-Mark.png
    ntfy_subtitle_prefix: GitHub Commit on
    ntfy_subtitle_seperator: by
    ntfy_tags: ['robot']
  [...]
  
feeds: # feeds to monitor from those services
  github_release: []
  github_commit: []
  [...]

config:
  cache_location: ~/.cache
  run_on_startup: false
  log_level: info
  schedule: '*/30 * * * *'                                      # crontab style expression - concurrent jobs are not possible
  service_wait: 60                                              # time to wait between services
  feed_wait: 5                                                  # time to wait between posts of one feed
  max_attempts: 3                                               # retry to send message; consider failed after
  retry_wait: 30                                                # time to wait between retrys
```

To personalize your rss ntfycations you can override / extend those defaults with a [config.yml](config/config.yml):  
With Docker: Don't mount the file directly and instead mount the whole config directory, otherwise automatic reload does not work.  
Without Docker: The script expects the config to be available at `/etc/rss-ntfy/config.yml`  

```yaml
---

global:
  ntfy_topic: some_topic                                        # topic to use if no other is defined on service level

feeds:
  reddit_subreddit:
    - SysadminHumor+Programmerhumor
  youtube:
    - name: UCXuqSBlHAE6Xw-yeJA0Tunw
      feed_display_name: LTT                                    # the subtitle takes the feed name - which in some cases, like YouTube, is an ID

services:
  reddit_subreddit:
    ntfy_topic: one_topic

  reddit_subreddit:
    ntfy_topic: another_topic
```

At this point the contents of the handlebar type substitutions (`{{ }}` in `services`) don't matter;  
this will be replaced with the users/thing-you-want-to-follow.

Changes are validated and applyied dynamicly. A reload / restart is not nessesary.

## License

Under the MIT License. See [license](/LICENSE) file for more information.
