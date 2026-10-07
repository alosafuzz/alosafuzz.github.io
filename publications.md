---
layout: default
title: Publications
permalink: /publications/
---
# Publications
<p class="lead">External and co-authored work, hosted elsewhere (Bishop Fox, etc.).
Linked here as part of the portfolio.</p>
<ul class="cards">
{% assign pubs = site.publications | sort: "date" | reverse %}
{% for p in pubs %}
  <li><a class="title" href="{{ p.url }}">{{ p.title }}</a> <span class="badge ext">{{ p.host }}</span>
  <div class="sub">{{ p.date | date: "%B %-d, %Y" }}{% if p.project %} · {{ p.project }}{% endif %}</div></li>
{% endfor %}
</ul>
