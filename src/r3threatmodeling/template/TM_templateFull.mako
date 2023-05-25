<%! import html %>
<%! from r3threatmodeling.r3threatmodeling import createTitleAnchorHash, makeMarkdownLinkedHeader  %>

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>

<%namespace name="lib" file="lib.mako"/> 


${lib.renderTMReportPart(tmo, ancestorData, toc=True, summary=True)}

% for descendantTM in tmo.getDescendants():
  ${lib.renderTMReportPart(descendantTM, ancestorData=False)}
% endfor

${makeMarkdownLinkedHeader(2, 'Requests For Information')}

__RFI_PLACEHOLDER__

