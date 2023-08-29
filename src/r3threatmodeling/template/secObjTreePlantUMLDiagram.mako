<%! import html %>\
<%! import textwrap %>\
<%! from r3threatmodeling.template_utils import unmark, createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>\
<%namespace name="lib" file="lib.mako"/>
<%
tmo = secObj.getRoot()
%>

<%def name="renderPlantUMLThreatTree(threat: Threatm, markdown=True)">\
${threat._id} [ fillcolor="#F8CECC", style=filled, shape=polygon, color="#B85450"
    label= 
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="center"><b>Threat</b><br/> ${lib.wrapText(threat.threatGeneratedTitle())}</td></tr>
     <tr><td align="center"><b>Impact</b><br/> ${lib.wrapText(valueOr(threat, 'impactDesc', ""))}</td></tr>   
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
    
${threat._id}_attack [ fillcolor="#f5f5f5", style=filled, shape=polygon, color="#666666", label =     
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="center"><b>Attack</b><br/>${lib.wrapText(threat.attack)}</td></tr>
   </table>>
    ]

${threat._id}_attack -> ${threat._id}  [label = " exploits"]

    % if len(threat.countermeasures) > 0:
    % for i, countermeasure in enumerate(threat.countermeasures):
     % if countermeasure.description is not None:
    ${threat._id}_countermeasure${i} [ 
       fillcolor="${countermeasure.statusColors()['fill']}", style=filled, shape=polygon, color="${countermeasure.statusColors()['border']}", label =     
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="left"><b>Countermeasure</b><br/> ${lib.wrapText(countermeasure.title)}</td></tr>
   </table>>
   ]

    ${threat._id}_countermeasure${i} -> ${threat._id}_attack [label = " mitigates"]

     % endif 
    % endfor
    % endif

</%def>

<% PlantUML_AT_HEAD="""@startuml
digraph G {
rankdir="RL";
  node [shape=plaintext, fontname="Arial" fontsize="12"];
    """%>\



${PlantUML_AT_HEAD}\

${secObj._id} [ fillcolor="#F8CECC", style=filled, shape=polygon, color="#B85450", label="${secObj._id}"]

% for threat in tmo.getAllDown('threats'):
     % for impactedSecObj in threat.impactedSecObjs:
          % if impactedSecObj.id == secObj.id: 
               ${renderPlantUMLThreatTree(threat=threat)}
               ${threat._id} -> ${secObj._id} [label = " impacts"]
          % endif     
     % endfor
% endfor





}

@enduml