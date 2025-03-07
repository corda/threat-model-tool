#!/usr/bin/env python3

# from lib2to3.pygram import pattern_symbols
# from pathvalidate import sanitize_filename
import os
from tokenize import String
import sys
import argparse
import time
import logging

import traceback
import html

from .threatmodel_data import *
# from markdown import Markdown
from .template_utils import *

import textwrap

customRed = "#B85450"

def wrap_text(text, width=80, limit=560):
    """
    Simple helper to wrap text so it fits neatly in the table cells.
    Truncates the text if it exceeds the limit and appends '[...]'.
    Also HTML-encodes the text to ensure special characters are properly displayed.
    """
    if not text:
        return ""
    if len(text) > limit:
        text = text[:limit] + '[...]'
    escaped_text = html.escape(text)
    wrapped_text = "<br/>".join(textwrap.wrap(escaped_text, width=width))
    return wrapped_text


def render_plant_uml_threat_tree(threat):
    """
    Generates a PlantUML threat tree diagram snippet, similar to the
    original Mako template output.
    """
    # Header portion
    fill_color = "#d3d3d3" if threat.fullyMitigated else "#F8CECC"
    output = f"""\
"{threat._id}" [ fillcolor="{fill_color}", style=filled, shape=polygon, color="{customRed}", penwidth=2,
    URL="../{threat.getRoot().id}.html#{threat._id}",  target="_top", 
    label= 
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="left"><b>{wrap_text(threat.title)}</b> 
     </td>  <td BGCOLOR="{threat.getSmartScoreColor()}">{threat.getSmartScoreDesc()}</td></tr>
     <tr><td align="center" COLSPAN="2">{wrap_text(threat.attack)}</td></tr>   
   </table>>
];
"""

    # Countermeasures portion
    if hasattr(threat, 'countermeasures') and threat.countermeasures:
        for i, cm in enumerate(threat.countermeasures):
            if cm.description:
                lineStyle = "solid" if cm.inPlace else "dashed" 
                fill_color = cm.statusColors()['fill'] # if cm.inPlace else "#F8CECC"
                lineColor = customRed if not cm.inPlace else "green"
                borderColor = cm.statusColors()['border'] #  "green" if cm.inPlace else customRed
                lineText =  "" if not cm.inPlace else "mitigates"
                output += f"""\
                
                
"{threat._id}_countermeasure{i}" [
    fillcolor="{fill_color}", style=filled, shape=polygon, penwidth=2,
    color="{borderColor}", 
    label=
    <<table border="0" cellborder="0" cellspacing="0">
      <tr><td align="left">
        <b>{wrap_text(cm.title)}</b><br/><br/> 
        {wrap_text(cm.description)}
      </td></tr>
    </table>>
]

"{threat._id}_countermeasure{i}" -> "{threat._id}" [label = " {lineText}", style="{lineStyle}", color="{lineColor}", penwidth=2]\n"""

    return output



def generate_attackTree_for_whole_threat_model_recursive(tmo):

    """
    Creates the PlantUML diagram for the entire threat model,
    similar to the Mako template (per_TM_AttackTreePlantUMLDiagram.mako).
    """
    diagram = ""
    # Diagram header (similar to the Mako variable PlantUML_AT_HEAD)
    if tmo.isRoot():
        diagram = textwrap.dedent("""\
        @startuml
        digraph G {
        rankdir="RL";
        node [shape=plaintext, fontname="Arial" fontsize="12"];
        """)

    # The main ThreatModel node
    diagram += f'''
"{tmo._id}" [fillcolor="#bae9ff", style=filled, shape=ellipse, color="{customRed}",
 label=
 <<table border="0" cellborder="0" cellspacing="0">
   <tr><td align="center">
     <b>{tmo._id}</b><br/>{wrap_text(getattr(tmo, 'description', ''))}
   </td></tr>
 </table>>]
'''

    # Threats
    if hasattr(tmo, 'threats'):
        for threat in tmo.threats:
            diagram += render_plant_uml_threat_tree(threat)
            diagram += f'"{threat._id}" -> "{tmo._id}" [label=" impacts"]\n'

    if hasattr(tmo, 'childrenTM'):
        for child in tmo.childrenTM:
            diagram += generate_attackTree_for_whole_threat_model_recursive(child)
            diagram += f'"{child._id}" -> "{tmo._id}" [label=" in scope for "]\n'

    # End the diagram
    if tmo.isRoot():
        diagram += "\n}\n@enduml\n"
        
    return diagram




def generate_plantuml_for_threat_model(tmo):
    """
    Creates the PlantUML diagram for the entire threat model,
    similar to the Mako template (per_TM_AttackTreePlantUMLDiagram.mako).
    """
    # Diagram header (similar to the Mako variable PlantUML_AT_HEAD)
    diagram = textwrap.dedent("""\
    @startuml
    digraph G {
      rankdir="RL";
      node [shape=plaintext, fontname="Arial" fontsize="12"];
    """)

    # The main ThreatModel node
    fillcolor = "#d3d3d3" if tmo.fullyMitigated else "#bae9ff"
    diagram += f'''
"{tmo._id}" [fillcolor="{fillcolor}", style=filled, shape=ellipse, color="red",
 label=
 <<table border="0" cellborder="0" cellspacing="0">
   <tr><td align="center">
     <b>{tmo._id}</b><br/>{wrap_text(getattr(tmo, 'description', ''))}
   </td></tr>
 </table>>]
'''

    # Threats
    if hasattr(tmo, 'threats'):
        for threat in tmo.threats:
            diagram += render_plant_uml_threat_tree(threat)
            diagram += f'"{threat._id}" -> "{tmo._id}" [label=" impacts"]\n'

    # End the diagram
    diagram += "\n}\n@enduml\n"
    return diagram

def generate_attackTree_for_whole_threat_model(tmo, praram_outputDir):
    outputDir = os.path.join(praram_outputDir, "img")
    os.makedirs(outputDir, exist_ok=True)
    try:
        # Create some basic PlantUML content about this ThreatModel
        # You can enrich this template as needed
        pumlText = generate_attackTree_for_whole_threat_model_recursive(tmo)

        # Write the output to a .puml file named after the ThreatModel's ID
        pumlFileName = os.path.join(outputDir, f"COMPLETE_{tmo._id}_ATTACKTREE.puml")
        with open(pumlFileName, "w", encoding="utf-8") as pumlFile:
            pumlFile.write(pumlText)

    except Exception:
        tb = traceback.format_exc()
        print(tb)


def generateAttackTreePerSingleTM(tmo, base_outputDir):
    """
    Generates a PlantUML file for each ThreatModel object (tmo),
    then recurses through any child threat models. This replaces
    the previous Mako-based rendering with a pure Python approach.
    """
    print(f"Generating Attack Tree for {tmo.id} in {base_outputDir}")
    outputDir = os.path.join(base_outputDir, "img")
    os.makedirs(outputDir, exist_ok=True)
    try:
        # Create some basic PlantUML content about this ThreatModel
        # You can enrich this template as needed
        pumlText = generate_plantuml_for_threat_model(tmo)

        # Write the output to a .puml file named after the ThreatModel's ID
        pumlFileName = os.path.join(outputDir, f"{tmo._id}_ATTACKTREE.puml")
        with open(pumlFileName, "w", encoding="utf-8") as pumlFile:
            pumlFile.write(pumlText)

        # Recurse if child ThreatModels exist
        if hasattr(tmo, 'childrenTM'):
            for child in tmo.childrenTM:
                parentOutputDir = os.path.join(base_outputDir, tmo._id)
                generateAttackTreePerSingleTM(child, parentOutputDir)

    except Exception:
        tb = traceback.format_exc()
        print(tb)
def generate_plantuml_for_threat_model(tmo):
    """
    Creates the PlantUML diagram for the entire threat model,
    similar to the Mako template (per_TM_AttackTreePlantUMLDiagram.mako).
    """
    # Diagram header (similar to the Mako variable PlantUML_AT_HEAD)
    diagram = textwrap.dedent("""\
    @startuml
    digraph G {
      rankdir="RL";
      node [shape=plaintext, fontname="Arial" fontsize="12", align="left"];
    """)

    # The main ThreatModel node
    fillcolor = "#bae9ff"
    diagram += f'''
"{tmo._id}" [fillcolor="{fillcolor}", style=filled, shape=ellipse, color="{customRed}",
 label=
 <<table border="0" cellborder="0" cellspacing="0">
   <tr><td align="left">
     <b>{wrap_text(tmo.title, width=27)}</b>
   </td></tr>
 </table>>]
'''

    # Threats
    if hasattr(tmo, 'threats'):
        for threat in tmo.threats:
            diagram += render_plant_uml_threat_tree(threat)
            # impactStatus =  "(fully-mitigated)" if threat.fullyMitigated() else "(unmitigated)"
            lineStyle = "solid" if not threat.fullyMitigated else "dashed"
            lineColor= customRed if not threat.fullyMitigated else "green"
            lineText = "impacts" if not threat.fullyMitigated else ""
            diagram += f'"{threat._id}" -> "{tmo._id}" [label="{lineText} ", color="{lineColor}", style="{lineStyle}", penwidth=2]\n' 
         

    # End the diagram
    diagram += "\n}\n@enduml\n"
    return diagram

def main():

    CLI=argparse.ArgumentParser()

    CLI.add_argument(
        "--rootTMYaml",
        default = None,
        required=True,
        type=open
    )

    CLI.add_argument(
        "--YAMLprefix",  
        default = "",
        required=False
    )

    CLI.add_argument(
    "--outputDir", 
    default = "build/img/",
    required=False
    )

    args = CLI.parse_args()
 
    tmo = ThreatModel(args.rootTMYaml)
    outputDir = args.outputDir

    generateAttackTreePerSingleTM(tmo, outputDir)

    generate_attackTree_for_whole_threat_model(tmo, outputDir)

    return 

if __name__ == "__main__":
    main()



