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
     <tr><td align="center"><b>${threat._id} ATTACK</b> <br/></td></tr>
     <tr><td align="center">${lib.wrapText(threat.attack)}</td></tr>
   </table>>
   ];
    

    % if len(threat.countermeasures) > 0:
    % for i, countermeasure in enumerate(threat.countermeasures):
     % if countermeasure.description is not None:
    ${threat._id}_countermeasure${i} [ 
       fillcolor="${countermeasure.statusColors()['fill']}", style=filled, shape=polygon, color="${countermeasure.statusColors()['border']}", label =     
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="left"><b> ${lib.wrapText(countermeasure.title)} (${countermeasure._id}) </b><br/><br/> ${lib.wrapText(countermeasure.description)} </td></tr>
   </table>>
   ]

    ${threat._id}_countermeasure${i} -> ${threat._id} [label = " mitigates"]

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

${secObj._id} [fillcolor="#bae9ff", style=filled shape=ellipse, color="#2bbcff", label="${secObj._id}", label= 
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="center"><b>${secObj._id}</b><br/>${lib.wrapText(secObj.description)}</td></tr>
   </table>>]

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