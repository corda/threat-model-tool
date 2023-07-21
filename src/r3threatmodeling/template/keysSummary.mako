<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

 
${makeMarkdownLinkedHeader(1, 'Keys classification ', skipTOC = False)}


__TOC_PLACEHOLDER__

${makeMarkdownLinkedHeader(2, 'Application specific keys and PKI assets ', skipTOC = False)}


Keys issued to processes to communicate in a secure manner, not linked to a specific business logic

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Title (ID)</th><th>Description</th><th>Properties</th></tr>
% for asset in tmo.getAssetsByProps(isApplicationKey=True):
<tr><td>${asset.title}<br/>(${asset.id})</td><td>
<b>${asset.type}</b><br>
${asset.description}</td>
<td>${asset.keyPropertiesHTML()}</td>
</tr>
% endfor ##asset
</table>

${makeMarkdownLinkedHeader(2, 'Infrastructure Keys and PKI assets', skipTOC = False)}


<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Title (ID)</th><th>Description</th><th>Properties</th></tr>
% for asset in tmo.getAssetsByProps(isInfrastructureKey=True):
<tr><td>${asset.title}<br/>(${asset.id})</td><td>
<b>${asset.type}</b><br>
${asset.description}</td>
<td>${asset.keyPropertiesHTML()}</td>
</tr>
% endfor ##asset
</table>





