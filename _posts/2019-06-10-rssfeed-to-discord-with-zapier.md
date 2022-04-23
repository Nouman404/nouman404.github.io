---
layout: post
title: '[Tutorial] RSSFeed to discord with Zapier'
date: 2019-06-10
categories: Tutorials
cover: 'https://s8333.pcdn.co/wp-content/uploads/edd/2015/07/zapier-product-image.png'
tags: automation
---
Tutorial How to make autopost bot discord from rss feed. [Alternative with Huginn](https://rokhimin.github.io/rssfeed-to-discord-with-huginn.rb)

*for example, if get new feed from website anime will be post to discord
[![example-rssfeed-discord-whd.md.jpg](https://s3.gifyu.com/images/example-rssfeed-discord-whd.md.jpg)](https://gifyu.com/image/EcKY)

# Flow
 Source Rss feed > (Zapier) RSS Feed > Formatter > Webhooks > Discord

# Setup Discord
- Server settings > webhooks > create webhooks
- save your webhooks url

# Setup Zapier
- go to https://zapier.com
- Create new apps

###### Rss Event
- [![rss1.md.jpg](https://s3.gifyu.com/images/rss1.md.jpg)](https://gifyu.com/image/EcNu)

###### Formatter Event (optional)
- Extract URL 
- [![formatter1.md.jpg](https://s3.gifyu.com/images/formatter1.md.jpg)](https://gifyu.com/image/EcNW)

###### Webhooks Event
- Action : Custom Request
- Method : POST
- Url : *your webhooks url*
- Data :  *example
-anime,manga

{% highlight plain %}
{
  "content": "***[UPDATE ANIME]*** @everyone",
  "embeds": [{
    "title": "__**{{title}}**__",
        "description": "```{{62099734__description}}```",
        "url": "{{62099734__link}}",
        "color": "1127128",
        "image": {
          "url": "https://images-ext-1.discordapp.net/external/b8iQQuKJVkT2HA5SwmyIRdNWDCAURYSKfeluMbrtCbw/https/i.grogol.us/img/aHR0cDovL2k2Ny50aW55cGljLmNvbS8yaTBzeTFzLmpwZw/grogol.jpg" 
          }
  }]
}
{% endhighlight %}

-Movie

{% highlight plain %}
{
  "content": "***[UPDATE MOVIE]*** @everyone",
  "embeds": [{
    "title": "__**{{title}}**__",
        "description": "```{{61591699__description}}```",
        "url": "{{61591699__link}}",
        "color": "1127128",
        "fields": [
      {
        "name": "Preview",
        "value": "https://{{61591895__output}}"
      }]
  }]
}
{% endhighlight %}

- [![jahd8383883.md.jpg](https://s3.gifyu.com/images/jahd8383883.md.jpg)](https://gifyu.com/image/EcNa)
- Headers : Content-Type | application/json
- test your app

thx for read :)

