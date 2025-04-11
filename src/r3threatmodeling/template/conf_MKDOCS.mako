<%! import html %>\
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>\
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>\
<%namespace name="lib" file="lib.mako"/>\
site_name: Threat Models
use_directory_urls: false
nav:
  - Home: 'index.md'
% for tm in tm_list:
    <%
        tmTitle = tm['title']
        tmName = tm['name']
        tmID   = tm['ID']
    %>
  - ${tmTitle}: '${tmID}/README.md'
% endfor

theme:
  name: readthedocs
  #navigation_depth: 4
  # features:
  #   - navigation.tabs
markdown_extensions:
  - toc:
      # permalink: ⚓︎
      # permalink_title: Copy link
      baselevel: 1
      toc_depth: 5
  - md_in_html
  - attr_list
  
plugins:
  # - mkdocs-nav-enhancements
  # - mkdocstrings:
  #     handlers:
  #       python:
  #         options:
  #           heading_level: 1
  # - search:
  # - with-pdf
  # - mkpdfs: broken
  #   # - company: R3 
  #   # - author: Security Team at R3
  # - print-site
  # - pdf-with-js:
  #     enable: true

extra_css:
  - css/mkdocs.css
  - css/threatmodel.css

extra_javascript:
  - js/tm.js
  
