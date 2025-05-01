<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%! from r3threatmodeling.ISO27001Report1 import renderISO27001Report %>

## False enables MKDOCS title metadata {}
<% ctx['useMarkDown_attr_list_ext'] = True %> 
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>

<%namespace name="lib" file="lib.mako"/> 


${lib.renderTMReportPart(tmo, ancestorData, toc=False, summary=True, )}

% for descendantTM in tmo.getDescendants():
  ${lib.renderTMReportPart(descendantTM, ancestorData=False, headerLevel=2)}
% endfor

${makeMarkdownLinkedHeader(2, 'Requests For Information', ctx)}

__RFI_PLACEHOLDER__

${PAGEBREAK}

<%include file="operationalHardeningGuide.mako" args="printTOC=False, headerLevel=2"/>

${PAGEBREAK}

<%include file="testingGuide.mako" args="printTOC=False, headerLevel=2"/>

${PAGEBREAK}

<%include file="keysSummary.mako" args="printTOC=False, headerLevel=2"/>

% if hasattr(tmo, 'ISO27001Ref') and tmo.ISO27001Ref:
${PAGEBREAK}
${renderISO27001Report(tmo, ctx, headerLevel=2)}
% endif


