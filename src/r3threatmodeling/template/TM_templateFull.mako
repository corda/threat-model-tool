<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%! from r3threatmodeling.ISO27001Report1 import render_summary %>
<%! from io import StringIO %>

## False enables MKDOCS title metadata {}
<% ctx['useMarkDown_attr_list_ext'] = False %> 

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>

<%namespace name="lib" file="lib.mako"/> 


${lib.renderTMReportPart(tmo, ancestorData, toc = True, summary=True, )}

% for descendantTM in tmo.getDescendants():
  ${lib.renderTMReportPart(descendantTM, ancestorData=False)}
% endfor

${PAGEBREAK}
${makeMarkdownLinkedHeader(2, 'Annex 1 Operational Hardening', ctx)}
<%include file="operationalHardeningGuide.mako" args="printTOC=False"/>

${PAGEBREAK}
${makeMarkdownLinkedHeader(2, 'Annex 2: Key Summary', ctx)}
<%include file="keysSummary.mako" args="printTOC=False"/>

% if hasattr(tmo, 'ISO27001Ref') and tmo.ISO27001Ref:
${PAGEBREAK}
${render_summary(tmo, ctx, headerLevel=2)}
% endif



