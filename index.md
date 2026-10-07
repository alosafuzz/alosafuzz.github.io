---
layout: default
title: null
---
# ICS/OT protocol security research

<p class="lead">I build protocol fuzzers and a safety-first scanner for industrial
control systems, reverse-engineer the wire formats they speak, and disclose what
I find. This site is the home for that work — the tools, the protocol guides, and
the writeups.</p>

## Start here
<ul class="cards">
  <li><a class="title" href="{{ '/projects/' | relative_url }}">Projects</a><div class="sub">The tools: icsFuzzer, icsScanner, and the sibling fuzzers.</div></li>
  <li><a class="title" href="{{ '/guides/' | relative_url }}">Protocol Guides</a><div class="sub">Research-focused field guides to ICS protocol wire formats and their fuzz surfaces.</div></li>
  <li><a class="title" href="{{ '/writeups/' | relative_url }}">Writeups</a><div class="sub">Narrative posts on methodology and findings.</div></li>
  {% if site.advisories.size > 0 %}<li><a class="title" href="{{ '/advisories/' | relative_url }}">Advisories</a><div class="sub">Coordinated-disclosure and CVE pages.</div></li>{% endif %}
</ul>
