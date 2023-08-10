<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%page args="printTOC=True"/>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

 
${makeMarkdownLinkedHeader(1, 'Keys classification ', skipTOC = False)}

% if printTOC:
__TOC_PLACEHOLDER__
% endif

<% appkeyassets=tmo.getAssetsByProps(isApplicationKey=True) %>
% if appkeyassets:
  ${makeMarkdownLinkedHeader(2, 'Application-specific keys', skipTOC = False)}
  Keys issued to processes to communicate in a secure manner, not linked to a specific business logic
  <%include file="keyTable.mako" args="assets=appkeyassets"/>
% endif

<% infrakeyassets=tmo.getAssetsByProps(isInfrastructureKey=True) %>
% if infrakeyassets:
  ${makeMarkdownLinkedHeader(2, 'Infrastructure Keys and PKI assets', skipTOC = False)}
  <%include file="keyTable.mako" args="assets=infrakeyassets"/>
% endif

<% credassets=tmo.getAssetsByProps(isCredential=True) %>
% if credassets:
  ${makeMarkdownLinkedHeader(2, 'Credentials', skipTOC = False)}
  <%include file="keyTable.mako" args="assets=credassets"/>
% endif




