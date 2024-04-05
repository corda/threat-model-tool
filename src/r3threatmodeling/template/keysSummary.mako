<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%page args="printTOC=True, headerLevel=1"/>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

 
 <%
 try:
  headerLevel
except:
  headerLevel=1
 %>
${makeMarkdownLinkedHeader(headerLevel, 'Keys classification ', skipTOC = False)}

% if printTOC:
__TOC_PLACEHOLDER__
% endif

<% appkeyassets=tmo.getAssetsByProps(applicationRelated=True, type='key') %>
% if appkeyassets:
  ${makeMarkdownLinkedHeader(headerLevel+1, 'Application-specific keys', skipTOC = False)}
  Keys issued to processes to communicate in a secure manner, not linked to a specific business logic
  <%include file="keyTable.mako" args="assets=appkeyassets"/>
% endif

<% infrakeyassets=tmo.getAssetsByProps(infrastructureRelated=True, type = 'key') %>
<% certassets=tmo.getAssetsByProps(type = 'certificate') %>
% if infrakeyassets or certassets:
  ${makeMarkdownLinkedHeader(headerLevel+1, 'Infrastructure Keys and PKI assets', skipTOC = False)}
  <%include file="keyTable.mako" args="assets=infrakeyassets"/>
  <%include file="keyTable.mako" args="assets=certassets"/>
% endif

<% credassets=tmo.getAssetsByProps(type='credential') %>
% if credassets:
  ${makeMarkdownLinkedHeader(headerLevel+1, 'Credentials', skipTOC = False)}
  <%include file="keyTable.mako" args="assets=credassets"/>
% endif




