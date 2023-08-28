<%! import html %>\
<%! import textwrap %>\
<%! from r3threatmodeling.template_utils import unmark, createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>\
<%namespace name="lib" file="lib.mako"/>\
<%def name="wrapText(input, columns=80)">\
${"<br/>".join(textwrap.wrap(unmark(input), columns))}\
</%def>\
<%def name="renderPlantUMLThreatTree(threat: Threatm, markdown=True)">\
<% PlantUML_AT_HEAD="""@startuml
digraph G {
rankdir="BT";
  node [shape=plaintext, fontname="Arial" fontsize="12"];
    """%>\
${PlantUML_AT_HEAD}\
threat [ fillcolor="#F8CECC", style=filled, shape=polygon, color="#B85450"
    label= 
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="center"><b>Threat</b><br/> ${wrapText(threat.threatGeneratedTitle())}</td></tr>
## % if hasattr(threat, 'impactDesc'):\
     <tr><td align="center"><b>Impact</b><br/>${wrapText(valueOr(threat, 'impactDesc', ""))}</td></tr>   
## % else:\
##      <tr><td align="center"><b>Impact</b><br/></td></tr>   \
## % endif
% if threat.impactedSecObjs:
     <tr><td><table border="0" cellborder="0" cellspacing="8"><tr>
% for secObj in threat.impactedSecObjs:
                ret += secObj.linkedImpactMDText()
     <td align="center" href="#${secObj.id}" bgcolor="#EEEEEE"><font color="blue">${secObj._id}</font></td>
% endfor      
     </tr></table></td></tr>   
% endif
   </table>>
   ];
    
attack [ fillcolor="#f5f5f5", style=filled, shape=polygon, color="#666666", label =     
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="center"><b>Attack</b><br/>${wrapText(threat.attack)}</td></tr>
   </table>>
    ]

attack -> threat [label = " exploits"]

    % if len(threat.countermeasures) > 0:
    % for i, countermeasure in enumerate(threat.countermeasures):
     % if countermeasure.description is not None:
    countermeasure${i} [ 
       fillcolor="${countermeasure.statusColors()['fill']}", style=filled, shape=polygon, color="${countermeasure.statusColors()['border']}", label =     
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="left"><b>Countermeasure</b><br/> ${wrapText(countermeasure.title)}</td></tr>
   </table>>
   ]

    countermeasure${i} -> attack [label = " mitigates"]

     % endif 
    % endfor
    % endif
}
@enduml
</%def>
${renderPlantUMLThreatTree(threat=threat)}
