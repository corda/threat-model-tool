<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

<% dataModel = tmo.getOperationalGuideData() %> 
 
${makeMarkdownLinkedHeader(1, 'Corda NextGen operational security hardening guides', skipTOC = False)}


__TOC_PLACEHOLDER__

% for operator, countermeasures in sorted(dataModel.items()):
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>

<% 
operatorName = operator
operatorObj= tmo.getRoot().getDescendantFirstById(operator)  
if operatorObj:
    operatorName = operatorObj.title
%>

${makeMarkdownLinkedHeader(1, 'Operational guide for ' + operatorName, skipTOC = False)}

% for countermeasure in countermeasures:

${makeMarkdownLinkedHeader(2, countermeasure.title.capitalize())}

**ID:** `${countermeasure.id}`

**Mitigates:** ${countermeasure.parent.title}

 %if hasattr(countermeasure, "operator"):
**Operated by: **${countermeasure.operator}
 %endif

% if  hasattr(threat, 'conditional'):
**Valid when:** ${threat.conditional}

% endif

${countermeasure.description}

% endfor # coutnermeasures

% endfor # oeprator




