<%! import html %>
<%! from r3threatmodeling.template_utils import globaUseMarkDownHeaders, createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
## False enables MKDOCS title metadata {}
<%! globaUseMarkDownHeaders = False %>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>

<%namespace name="lib" file="lib.mako"/> 


${lib.renderTMReportPart(tmo, ancestorData, toc=False, summary=True, )}

% for descendantTM in tmo.getDescendants():
  ${lib.renderTMReportPart(descendantTM, ancestorData=False, headerLevel=2)}
% endfor

${makeMarkdownLinkedHeader(2, 'Requests For Information')}

__RFI_PLACEHOLDER__

${PAGEBREAK}

<%include file="operationalHardeningGuide.mako" args="printTOC=False, headerLevel=2"/>

${PAGEBREAK}

<%include file="testingGuide.mako" args="printTOC=False, headerLevel=2"/>

${PAGEBREAK}

<%include file="keysSummary.mako" args="printTOC=False, headerLevel=2"/>




