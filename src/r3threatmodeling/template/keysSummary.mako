<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

 
${makeMarkdownLinkedHeader(1, 'Keys classification ', skipTOC = False)}


__TOC_PLACEHOLDER__

${makeMarkdownLinkedHeader(2, 'Infrastructure keys', skipTOC = False)}

Keys issued to processes to communicate in a secure manner, not linked to a specific business logic

% for asset in tmo.getAssetsByProps(type="key"):

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Key</th><th>Format</th><th>Storage</th><th>Additional information</th></tr>
<tr><td>${asset.id}</td><td>Format</td><td>Storage</td><td>Additional information</td></tr>
</table>
${lib.renderAsset(asset)} 

#if hasattr(asset, "lenght"):
    ${asset.lenght}


% endfor ##asset

${makeMarkdownLinkedHeader(2, 'Credentials', skipTOC = False)}

% for asset in tmo.getAssetsByProps(type="credential"):

${lib.renderAsset(asset)} 

% endfor ##asset



% for asset in tmo.getAssetsByProps(type="credentials"):

${lib.renderAsset(asset)} 

% endfor ##asset


${makeMarkdownLinkedHeader(2, 'Businesss keys', skipTOC = False)}

Keys issued to business actors and linked to a specific business logic

% for asset in tmo.getAssetsByProps(isBusinessKey=True):

${lib.renderAsset(asset)} 

% endfor ##asset


