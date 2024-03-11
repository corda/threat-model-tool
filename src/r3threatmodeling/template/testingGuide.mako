<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%page args="printTOC=True"/>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 

## <% dataModel = tmo.getOperationalGuideData() %> 
 
${makeMarkdownLinkedHeader(1, 'Testing guide', skipTOC = False)}


This guide lists all testable attacks described in the threat model

<table>
<tr><th>Seq</th><th>Test ID</th><th>Attack to test</th><th>Pass/Fail/NA</th></tr>
<tr>

<%
    ts = [t for t in tmo.getAllDown('threats') if ( hasattr(t, 'pentestTestable') and t.pentestTestable is True)]
%>

% for idx, threat in enumerate(ts):

## ${makeMarkdownLinkedHeader(3, threat.ID + " Test")}
<td>${idx+1}</td><td> ${threat.ID}</td>
<td>${threat.attack}
% if  hasattr(threat, 'conditional'):
\n**Valid when:** ${threat.conditional}
% endif
</td>
<td></td>

</tr>
% endfor # threats
</table>




