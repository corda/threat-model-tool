<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<%namespace name="lib" file="lib.mako"/> 

# Threat Models

% for tm in tm_list:
    <%
        tmTitle = tm['title']
        tmName = tm['name']
        tmID   = tm['ID']
    %>
<a href="${tmID}/${tmID}.html">${tmTitle}</a>
##   (${tmTitle})[${tmID}/${tmID}.html]
% endfor

## WARNING: this content is R3 private and confidential


