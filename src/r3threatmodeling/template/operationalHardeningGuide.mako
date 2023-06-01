<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 


% for descendantTM in tmo.getDescendants():
  % for threat in descendantTM.threats:
    <% cms = threat.getOperationalCountermeasures() %>
    % for countermeasure in cms:

% if not countermeasure.isReference :

${makeMarkdownLinkedHeader(2, countermeasure.title.capitalize())}
**ID:** `${countermeasure.id}`
### <br/>

## % else:
## **Reference to `${countermeasure.id}` ${countermeasure.title}**<br/>

**Mitigates:** ${countermeasure.parent.title}

 %if hasattr(countermeasure, "operator"):
**Operated by: **${countermeasure.operator}
 %endif

% if  hasattr(threat, 'conditional'):
**Valid when:** ${threat.conditional}
## % else:
## Always valid
% endif

${countermeasure.description}

% endif #REFID

    % endfor
  % endfor

% endfor

## ${makeMarkdownLinkedHeader(2, 'Requests For Information')}


