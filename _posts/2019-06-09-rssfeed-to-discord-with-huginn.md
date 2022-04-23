---
layout: post
title: '[Tutorial] RSSFeed to discord with Huginn'
date: 2019-06-09
categories: Tutorials
cover: 'https://s3.gifyu.com/images/bRbiKTIgzlOxELuPpm71BQlLmPujDKtnyhQhiSC_uoX4OCzX-SVLu8rTW3dFIhF89VIDpcomHDKjBUGMCh4bPg63J4c2INAkb0WtEKUw5000-h5000.png'
tags: automation
---

Tutorial How to make autopost bot discord from rss feed website. this is like using zapier [ [rssfeed>discord with zapier](https://rokhimin.github.io/rssfeed-to-discord-with-zapier.rb) ]

# Event Flow
[![flowevent.jpg](https://s3.gifyu.com/images/flowevent.jpg)](https://gifyu.com/image/EcJS)

# Setup Discord
- Server settings > webhooks > create webhooks
- save your webhooks url

# Setup Huginn
- Deploy [Huginn](https://github.com/rokhimin/huginn-test) to your server ( I recommended Heroku )

###### Rss Agent
- schedule : 1m (5m,10m whatever)
- receiver : formatter agent
- set your url rss feed

{% highlight plain %}
{
  "expected_update_period_in_days": "5",
  "url": [
    "http://www.grogol.us/news/rss.php",
    "http://www.grogol.us/news/rssmanga.php",
    "http://www.grogol.us/news/rssblog.php"
  ],
  "clean": "false"
}
{% endhighlight %}

###### Formatter Agent
- (Optional) You can use a trigger agent
- source : rss agent
- receiver : post agent
- example

{% highlight plain %}
{
  "instructions": {
    "content": " content | strip_html  ",
    "description": "{{ jpg_url.0 | append: '.jpg' }}",
    "title": "title",
    "url": "url"
  },
  "matchers": [
    {
      "path": "description",
      "regexp": "(?<=src=\").+(?=.jpg)",
      "to": "jpg_url"
    }
  ],
  "mode": "clean"
}
{% endhighlight %}
- use [liquid filter](https://help.shopify.com/en/themes/liquid/filters/string-filters) to filtering your rss

###### Post Agent
- schedule : never
- source : formatter agent
- example
{% highlight plain %}
{
  "post_url": "https://discordapp.com/api/webhooks/595513961873670144/sgcJcOL8c9Sgkw4f8wAaiwajwPPn-cjQRixbB3ZMDmP7fcadHaZwsQDqiY1h1tx77604",
  "expected_receive_period_in_days": "4",
  "content_type": "json",
  "method": "post",
  "payload": {
    "content": "***[UPDATE ANIME]*** @everyone ",
    "embeds": [
      {
        "title": "__**{{title}}**__",
        "description": "```content```",
        "url": "url ",
        "color": "1127128",
        "image": {
          "url": "description"
        }
      }
    ]
  },
  "emit_events": "true",
  "no_merge": "true",
  "output_mode": "clean"
}
{% endhighlight %}
- dry run to test

[![rssdiscord-whd-28922.jpg](https://s3.gifyu.com/images/rssdiscord-whd-28922.jpg)](https://gifyu.com/image/EcJq)




Thankyou :)



