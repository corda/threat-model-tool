<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>

<%namespace name="lib" file="lib.mako"/> 


${lib.renderTMReportPart(tmo, ancestorData, toc=True, summary=True)}

% for descendantTM in tmo.getDescendants():
  ${lib.renderTMReportPart(descendantTM, ancestorData=False)}
% endfor

${makeMarkdownLinkedHeader(2, 'Requests For Information')}

__RFI_PLACEHOLDER__

${PAGEBREAK}
${makeMarkdownLinkedHeader(1, 'Annex 1')}
<%include file="operationalHardeningGuide.mako" args="printTOC=False"/>

${PAGEBREAK}
${makeMarkdownLinkedHeader(1, 'Annex 2')}
<%include file="keysSummary.mako" args="printTOC=False"/>




