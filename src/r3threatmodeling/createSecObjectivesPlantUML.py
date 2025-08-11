#!/usr/bin/env python3

# from lib2to3.pygram import pattern_symbols
from pathvalidate import sanitize_filename
import os
from tokenize import String
import yaml
import sys
import argparse
import time
import logging
from watchdog.observers import Observer
from watchdog.events import LoggingEventHandler, PatternMatchingEventHandler
import traceback

from .threatmodel_data import *
from markdown import Markdown
from .template_utils import *
import re


def generate(tmo, outputDir, outputFilename = "secObjectives.puml", template="secObjectivesPlantUMLDiagram"):
    """
    Direct (non-Mako) implementation of the previous template logic.
    Builds a PlantUML (DOT) diagram showing security objectives and their contributesTo links.
    """
    try:
        lines = []
        lines.append("@startuml")
        lines.append("digraph G {")
        lines.append(' rankdir="BT";')
        lines.append(' ranksep=2;')
        lines.append('  node [fontname="Arial" fontsize="14" color=LightGray style=filled shape="box"];')
        lines.append("")  # blank line

        security_objectives = list(getattr(tmo, "securityObjectives", []))

        # Collect edges and group membership
        edges = []
        groups = {}
        group_members = {}
        for so in security_objectives:
            group = getattr(so, "group", "") or ""
            groups[so._id] = group
            group_members.setdefault(group, []).append(so._id)
            for parentSO in getattr(so, "contributesTo", []) or []:
                # Proper DOT edge with label
                edges.append((so._id, parentSO._id))

        # Emit groups (one subgraph per group)
        for group, members in group_members.items():
            # Sanitize cluster id (Graphviz id rules)
            cluster_id_raw = re.sub(r"\s+", "_", group) if group else "Ungrouped"
            cluster_id = re.sub(r"[^A-Za-z0-9_]", "_", cluster_id_raw)
            label = group.replace('"', '\\"')
            node_list = " ".join(f"\"{m}\";" for m in members)
            lines.append(f"subgraph cluster_{cluster_id} {{  label = \"{label}\";  {node_list} }}")

        # Emit edges after clusters
        for child, parent in edges:
            lines.append(f"\"{child}\" -> \"{parent}\" [label = \"contributes to\"]")

        # Close (commented-out legacy threat-to-secObj block retained as comments to keep parity)
        lines.append("")
        lines.append("## (threat -> secObj edges omitted)")
        lines.append("")
        lines.append("}")
        lines.append("@enduml")

        outText = "\n".join(lines)

        os.makedirs(outputDir, exist_ok=True)
        outputPath = os.path.join(outputDir, outputFilename)
        with open(outputPath, "w") as f:
            print(f"OUTPUT: {f.name}")
            f.write(outText)
    except Exception as e:
        print(f"Error generating sec objectives diagram: {e}")


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

    CLI.add_argument(
    "--template",
    # default = "TM_template",
    required=False,
    default="secObjectivesPlantUMLDiagram"
    )
    CLI.add_argument(
    "--outputFilename",
    default = "secObjectives.puml",
    required=False
    )

    args = CLI.parse_args()

    template = args.template
    outputFilename = args.outputFilename 
    tmo = ThreatModel(args.rootTMYaml)
    outputDir = args.outputDir


    generate(tmo, outputDir, outputFilename, template)
    return 

if __name__ == "__main__":
    main()