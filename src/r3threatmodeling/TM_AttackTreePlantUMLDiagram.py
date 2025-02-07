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

def wrap_text(text, width=80):
    """
    Simple helper to wrap text so it fits neatly in the table cells.
    Also HTML-encodes the text to ensure special characters are properly displayed.
    """
    if not text:
        return ""
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
{threat._id} [ fillcolor="{fill_color}", style=filled, shape=polygon, color="#B85450"
    label= 
    <<table border="0" cellborder="0" cellspacing="0">
     <tr><td align="center"><b>{threat._id} ATTACK</b> <br/></td></tr>
     <tr><td align="center">{wrap_text(threat.attack)}</td></tr>
   </table>>
];
"""

    # Countermeasures portion
    if hasattr(threat, 'countermeasures') and threat.countermeasures:
        for i, cm in enumerate(threat.countermeasures):
            if cm.description:
                lineStyle = "solid" if cm.inPlace else "dashed" 
                fill_color = "#d3d3d3" if cm.inPlace else "#F8CECC"
                lineColor = "red" if not cm.inPlace else "green"
                output += f"""\

{threat._id}_countermeasure{i} [
    fillcolor="{fill_color}", style=filled, shape=polygon, 
    color="{cm.statusColors()['border']}", 
    label=
    <<table border="0" cellborder="0" cellspacing="0">
      <tr><td align="left">
        <b>{wrap_text(cm.title)} ({cm._id})</b><br/><br/> 
        {wrap_text(cm.description)}
      </td></tr>
    </table>>
]

{threat._id}_countermeasure{i} -> {threat._id} [label = " mitigates", style="{lineStyle}", color="{lineColor}", penwidth=3]\n' ]

"""

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
"{tmo._id}" [fillcolor="#bae9ff", style=filled, shape=ellipse, color="#2bbcff",
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
"{tmo._id}" [fillcolor="{fillcolor}", style=filled, shape=ellipse, color="#2bbcff",
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


def generateAttachTreePerSingleTM(tmo, base_outputDir):
    """
    Generates a PlantUML file for each ThreatModel object (tmo),
    then recurses through any child threat models. This replaces
    the previous Mako-based rendering with a pure Python approach.
    """
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
                generateAttachTreePerSingleTM(child, parentOutputDir)

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
      node [shape=plaintext, fontname="Arial" fontsize="12"];
    """)

    # The main ThreatModel node
    fillcolor = "#bae9ff"
    diagram += f'''
"{tmo._id}" [fillcolor="{fillcolor}", style=filled, shape=ellipse, color="#2bbcff",
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
            # impactStatus =  "(fully-mitigated)" if threat.fullyMitigated() else "(unmitigated)"
            lineStyle = "solid" if not threat.fullyMitigated else "dashed"
            lineColor= "red" if not threat.fullyMitigated else "green"
            diagram += f'"{threat._id}" -> "{tmo._id}" [label=" impacts ", color="{lineColor}", style="{lineStyle}", penwidth=3]\n' 
         

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

    generateAttachTreePerSingleTM(tmo, outputDir)

    generate_attackTree_for_whole_threat_model(tmo, outputDir)

    return 

if __name__ == "__main__":
    main()



