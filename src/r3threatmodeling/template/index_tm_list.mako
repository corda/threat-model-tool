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

% for tm in tm_list:
<h2>Latest SNAPSHOT</h2>

Latest published SNAPSHOT: __VERSION__ <br/>
Generated on: __TIMEGEN__
<p><a href="${tm['path']}/${tm['name']}.html">HTML version</a></p><br/>
<p><a href="__PDF_FILENAME__">PDF version</a></p><br/>
<p><a href="https://github.com/corda/threat-modeling/blob/master/threatModels/${tm['name']}">Source (yaml)</a></p><br/>
<p><a href="CordaHardeningGuide.html">Security hardening operational guides (PoC)</a></p><br/>
<p><a href="keysSummary.html">Keys and crypto sensitive assets summary report annex(PoC)</a></p><br/>

% endfor
</body>
</html>
