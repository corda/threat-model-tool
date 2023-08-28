<%! import html %>
<%! import re %>
<%! import textwrap %>

<%! from r3threatmodeling.template_utils import unmark, createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%namespace name="lib" file="lib.mako"/> 


<%def name="wrapText(input, columns=80)">
${"<br/>".join(textwrap.wrap(unmark(input), columns))}
</%def>

<%def name="renderPlantUMLSecObjectivesTree(tmo, markdown=True)">
<% PlantUML_AT_HEAD="""
@startuml
digraph G {
rankdir="BT";
  node [fontname="Arial" fontsize="12" color=green];

    """

%>

${PlantUML_AT_HEAD}

% for i, so in enumerate(tmo.securityObjectives):
    % for parentSO in so.contributesTo:
${so._id} -> ${parentSO._id} ## [label = "contributes to"]
subgraph cluster_${re.sub("\s", "_", so.group)} {  label = "${so.group}";  ${so._id}; }
    % endfor
% endfor
## % for i, threat in enumerate(tmo.getAllDown('threats')):
##   % if threat.impactedSecObjs:
##       % for secObj in threat.impactedSecObjs:
##           ${re.sub("\-", "_", threat._id)} -> ${secObj._id}
##       % endfor
##   % endif
## % endfor

}
@enduml
</%def>

${renderPlantUMLSecObjectivesTree(tmo=tmo)}
