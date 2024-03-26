<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%page args="printTOC=True, headerLevel=1"/>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

<% dataModel = tmo.getOperationalGuideData() %> 

${makeMarkdownLinkedHeader(headerLevel, 'Operational security hardening guides', skipTOC = False)}

% if printTOC:
__TOC_PLACEHOLDER__
% endif

% for operator, countermeasures in sorted(dataModel.items()):
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>

<% 
operatorName = operator
operatorObj= tmo.getRoot().getDescendantFirstById(operator)  
if operatorObj:
    operatorName = operatorObj.title
%>

${makeMarkdownLinkedHeader(headerLevel +1, 'Operational guide for ' + operatorName, skipTOC = False)}

% for countermeasure in countermeasures:

${makeMarkdownLinkedHeader(headerLevel+2, countermeasure.title.capitalize())}

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




