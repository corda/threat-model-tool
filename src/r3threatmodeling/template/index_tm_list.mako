<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<% PAGEBREAK = """<div class="pagebreak"></div>"""%>
<% H6 = "######" %>
<%namespace name="lib" file="lib.mako"/> 
<!DOCTYPE html>
<html>
    <head>
        <title>R3 Threat Model Repository</title>
        <link rel="stylesheet" href="css/tm.css">
      </head>
<body>

    <h2 style="color: crimson;">WARNING: this content is R3 private and confidential  </h2>

<h1>R3 Threat Model Repository</h1>

% for ver in versions:
<div id="version-${ver}">

<h2>Version: ${ver}</h2>
<table>
<thead>
<tr>
<th>Threat Model</th><th>PDF Report</th><th>Source</th><th>Hardening Guide</th><th>Key Summary</th>
</tr>
</thead>
<tbody>
% for tm in tm_list:
    <%
        tmOutputDir = ver + '/' + tm['name']
        tmName = tm['name']
        tmPDF  = tm['pdf']
    %>
    <tr>
    <td><a href="${tmOutputDir}/${tmName}.html">${tmName}</a></td>
    <td><a href="${tmOutputDir}/${tmPDF}">${tmPDF}</a></td>
    <td><a href="https://github.com/corda/threat-modeling/blob/master/threatModels/${tm['name']}">Source (yaml)</a></td>
    <td><a href="${tmOutputDir}/HardeningGuide.html">Security hardening guide (${tmName})</a></td>
    <td><a href="${tmOutputDir}/KeySummary.html">Keys summary (${tmName})</a></td>
    </tr>
% endfor
</tbody>
</table>
</div>
% endfor

</body>
</html>
