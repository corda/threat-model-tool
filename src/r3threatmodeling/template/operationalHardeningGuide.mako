<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%page args="printTOC=True, headerLevel=1"/>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

<% dataModel = tmo.getOperationalGuideData() %> 

${makeMarkdownLinkedHeader(headerLevel, 'Operational security hardening guides', ctx, skipTOC = False)}

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

${makeMarkdownLinkedHeader(headerLevel +1, 'Operational guide for ' + operatorName, ctx, skipTOC = False)}


<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <tr>
    <th>Seq</th><th>Countermeasure</th>
  </tr>
% for i, countermeasure in enumerate(countermeasures):
<tr markdown="block">
<td>${i+1}</td>
<td markdown="block">


**Title (ID):** ${countermeasure.title} (`${countermeasure._id}`)

**Mitigates:** <a href="#${countermeasure.parent.id}">${countermeasure.parent.title}</a>

##  %if hasattr(countermeasure, "operator"):
## **Operated by: **${countermeasure.operator}
##  %endif
**Description:**
% if  hasattr(threat, 'conditional'):
**Valid when:** ${threat.conditional}

% endif
<br/>
${countermeasure.description}
</td>
</tr>
% endfor # coutnermeasures

</table>

% endfor # operator




