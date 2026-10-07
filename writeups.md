---
layout: default
title: Writeups
permalink: /writeups/
---
# Writeups
<ul class="cards">
{% assign ws = site.writeups | sort: "date" | reverse %}
{% for p in ws %}
  <li><a class="title" href="{{ p.url | relative_url }}">{{ p.title }}</a>
  <div class="sub">{{ p.date | date: "%B %-d, %Y" }}{% if p.summary %} — {{ p.summary }}{% endif %}</div></li>
{% endfor %}
</ul>
