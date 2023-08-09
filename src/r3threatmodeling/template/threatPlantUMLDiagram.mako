<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>
<%namespace name="lib" file="lib.mako"/> 



<%def name="renderPlantUMLThreatTree(threat: Threatm, markdown=True)">
<% PlantUML_AT_HEAD="""

@startuml
digraph G {
rankdir="BT";


    """

%>

${PlantUML_AT_HEAD}


    T1["<b>Threat:</b> ${mermaid_escape(threat.threatGeneratedTitle())}
    <b>Impact:</b> ${mermaid_escape(valueOr(threat, 'impact_desc', "TOO add impact info"))} 
    
    "]:::threat
    A1["<b>Attack:</b> ${getShortDescForMermaid(threat.attack , 290)}"]:::attack --exploits--> T1
    % if len(threat.countermeasures) > 0:
    % for countermeasure in threat.countermeasures:
     % if countermeasure.description is not None:
    C${countermeasure.id}["<b>Countermeasure:</b> ${mermaid_escape(countermeasure.title)}"]:::${countermeasure.RAGStyle()} --mitigates--> A1

     % endif 
    % endfor
    % endif

</%def>