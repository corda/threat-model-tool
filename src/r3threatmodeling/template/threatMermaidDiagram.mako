<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%namespace name="lib" file="lib.mako"/> 
${lib.renderMermaidThreatTree(threat, markdown = False)}