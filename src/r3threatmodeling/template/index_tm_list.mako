<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 
<!DOCTYPE html>
<html>
    <head>
        <title>Corda 5 NextGen Threat Model</title>
        <link rel="stylesheet" href="css/tm.css">
      </head>
<body>

    <h2 style="color: crimson;">WARNING: this content is R3 private and confidential  </h2>

<h1>Corda 5 NextGen Threat Model -- WORK IN PROGRESS --</h1>

<h2>Latest RELEASE </h2> 
<a href="https://github.com/corda/threat-modeling/archive/refs/tags/2023.v1-DRAFT.zip">
    2023.v1-DRAFT (ZIP file containing PDF)
</a> 



<h2>Latest SNAPSHOT</h2>
Latest published SNAPSHOT: __VERSION__ <br/>
Generated on: __TIMEGEN__

<table>
<thead>
<tr>
<th>Threat Model</th><th>PDF Report</th><th>Source</th><th>Hardening Guide</th><th>Key Summary</th>
</tr>
</thead>
<tbody>
% for tm in tm_list:
    <%
        tmOutputDir = tm['name'] 
        tmName = tm['name']
        tmPDF  = tm['pdf']
    %>
    <tr>
    <td><a href="${tmOutputDir}/${tmName}.html">${tmName}</a></td>
    <td><a href="${tmOutputDir}/${tmPDF}">${tmPDF}</a></td>
    <td><a href="https://github.com/corda/threat-modeling/blob/master/threatModels/${tm['name']}">Source (yaml)</a></td>
    <td><a href="${tmOutputDir}/SecurityGuide.html">Security hardening guide (${tmName})</a></td>
    <td><a href="${tmOutputDir}/KeysSummary.html">Keys summary (${tmName})</a></td>
    </tr>
% endfor
</tbody>
</table>

</body>
</html>
