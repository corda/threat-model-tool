<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

 
${makeMarkdownLinkedHeader(1, 'Keys classification ', skipTOC = False)}


__TOC_PLACEHOLDER__

${makeMarkdownLinkedHeader(2, 'Infrastructure keys', skipTOC = False)}

Keys issued to processes to communicate in a secure manner, not linked to a specific business logic

% for asset in tmo.getAssetsByProps(isInfrastructureKey=True):

${lib.renderAsset(asset)} 

% endfor ##asset

${makeMarkdownLinkedHeader(2, 'Businesss keys', skipTOC = False)}

Keys issued to business actors and linked to a specific business logic

% for asset in tmo.getAssetsByProps(isBusinessKey=True):

${lib.renderAsset(asset)} 

% endfor ##asset


