---
layout: default
title: Advisories
permalink: /advisories/
---
# Advisories
<p class="lead">Coordinated-disclosure and CVE pages. TLP-marked.</p>
<ul class="cards">
{% assign a = site.advisories | sort: "date" | reverse %}
{% for p in a %}
  <li><a class="title" href="{{ p.url | relative_url }}">{{ p.title }}</a>
  <div class="sub">{% if p.cve %}{{ p.cve | join: ", " }} · {% endif %}{{ p.date | date: "%B %-d, %Y" }}</div></li>
{% endfor %}
</ul>
