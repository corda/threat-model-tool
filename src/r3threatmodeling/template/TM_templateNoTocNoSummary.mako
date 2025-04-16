<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
## False enables MKDOCS title metadata {}
<% ctx['useMarkDown_attr_list_ext'] = False %> 

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>

<%namespace name="lib" file="lib.mako"/> 


${lib.renderTMReportPart(tmo, ancestorData, toc = False, summary=False, )}

% for descendantTM in tmo.getDescendants():
  ${lib.renderTMReportPart(descendantTM, ancestorData=False)}
% endfor

## ${PAGEBREAK}
## ${makeMarkdownLinkedHeader(2, 'Annex 1 Operational Hardening', ctx)}
## <%include file="operationalHardeningGuide.mako" args="printTOC=False"/>

${PAGEBREAK}
${makeMarkdownLinkedHeader(2, 'Annex 1: Keys Summary', ctx)}
<%include file="keysSummary.mako" args="printTOC=False"/>

