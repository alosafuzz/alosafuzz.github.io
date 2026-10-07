---
layout: default
title: Projects
permalink: /projects/
---
# Projects
<p class="lead">The alosafuzz research program — each tool is its own project.</p>
<ul class="cards">
{% assign ps = site.projects | sort: "order" %}
{% for p in ps %}
  <li><a class="title" href="{{ p.url | relative_url }}">{{ p.title }}</a>
  <div class="sub">{{ p.summary }} <span class="badge">{{ p.status }}</span></div></li>
{% endfor %}
</ul>
