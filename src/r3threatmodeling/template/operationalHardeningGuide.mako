<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%page args="printTOC=True, headerLevel=1"/>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

<% 
# Get all operational countermeasures and sort them, perhaps by ID or title
all_operational_cms = []
for operator, countermeasures in sorted(tmo.getOperationalGuideData().items()):
    all_operational_cms.extend(countermeasures)
# Sort all countermeasures, e.g., by ID. Adjust sorting as needed.
all_operational_cms.sort(key=lambda cm: cm._id) 
%> 

${makeMarkdownLinkedHeader(headerLevel, 'Operational Security Hardening Guide', ctx, skipTOC = False)}

% if printTOC:
__TOC_PLACEHOLDER__
% endif

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
  <thead>
  <tr>
    <th>Seq</th><th>Countermeasure Details</th>
  </tr>
  </thead>
  <tbody markdown="block">
% for i, countermeasure in enumerate(all_operational_cms):
<tr markdown="block">
<td>${i+1}</td>
<td markdown="block">
**Title (ID):** ${countermeasure.title} (`${countermeasure._id}`)
<br/>
**Mitigates:** <a href="#${countermeasure.parent.anchor}">${countermeasure.parent.title}</a> (`${countermeasure.parent._id}`)
<br/>

**Description:**
% if hasattr(countermeasure.parent, 'conditional'): ## Check parent threat for conditional
**Valid when:** ${countermeasure.parent.conditional}
<br/>
% endif
${countermeasure.description}

% if countermeasure.operator and countermeasure.operator != "UNDEFINED":
**Operated by:** ${countermeasure.operator}
<br/>
% endif

</td>
</tr>
% endfor # all_operational_cms
</tbody>
</table>




