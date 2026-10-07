---
layout: default
title: Protocol Guides
permalink: /guides/
---
# Protocol Guides
<p class="lead">Research-focused field guides for fuzzing and vulnerability
researchers — wire format, the fuzz surface, published bug classes, and how to
build a test harness. Defensive framing; no weaponized exploit code. Indexed by
vendor / ecosystem.</p>
{% assign byvendor = site.guides | sort: "title" | group_by_exp: "g", "g.vendor_group" %}
{% for grp in byvendor %}
<h2>{{ grp.name }}</h2>
<ul class="cards">
{% for g in grp.items %}
  <li><a class="title" href="{{ g.url | relative_url }}">{{ g.title }}</a>
  <div class="sub">{{ g.protocols | join: ", " }}{% if g.transport %} · {{ g.transport | join: ", " }}{% endif %}</div></li>
{% endfor %}
</ul>
{% endfor %}
