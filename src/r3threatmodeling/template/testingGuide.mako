<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%page args="printTOC=True, headerLevel=1"/>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<%namespace name="lib" file="lib.mako"/> 

## <% dataModel = tmo.getOperationalGuideData() %> 
 
${makeMarkdownLinkedHeader(headerLevel, 'Testing guide', ctx , skipTOC = False)}


This guide lists all testable attacks described in the threat model

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Seq</th><th>Attack to test</th><th>Pass/Fail/NA</th></tr>
<tr markdown="block">

<%
    ts = [t for t in tmo.getAllDown('threats') if ( hasattr(t, 'pentestTestable') and t.pentestTestable is True)]
%>

% for idx, threat in enumerate(ts):

## ${makeMarkdownLinkedHeader(3, threat.ID + " Test")}
<td>${idx+1}</td>
<td markdown="block">
<a href="#${threat.id}">${threat.title}</a><br/>
**Attack description:** ${threat.attack}
% if  hasattr(threat, 'conditional'):
\n**Valid when:** ${threat.conditional}
% endif
</td>
<td></td>

</tr>
% endfor # threats
</table>




