#!/usr/bin/env python3

# from lib2to3.pygram import pattern_symbols
from pathvalidate import sanitize_filename
import os
import argparse
import traceback

from ..threatmodel_data import *
from .template_utils import unmark
import textwrap
import html

CUSTOM_RED = "#B85450"

def _wrap_text(text: str, width: int = 80, limit: int = 77 * 4) -> str:
    """Best‑effort reproduction of lib.wrapText() in the legacy Mako template.

    - Strip basic markdown via unmark (already escapes HTML)
    - Truncate overly long text adding trailing '[...]'
    - Wrap to a given width and join lines with <br/>
    """
    if not text:
        return ""
    # unmark will also escape HTML entities
    try:
        plain = unmark(text)
    except Exception:  # pragma: no cover
        plain = html.escape(text)
    if len(plain) > limit:
        plain = plain[:limit] + "[...]"
    wrapped = textwrap.wrap(plain, width=width)
    return "<br/>".join(wrapped) if wrapped else ""


def _impacted_secobjs(threat):
    return getattr(threat, 'impactedSecObjs', None) or getattr(threat, 'impactedSecObj', []) or []


def _render_threat_block(threat):
    """Return PlantUML snippet for a threat + its countermeasures (without trailing newline)."""
    buf = []
    buf.append(f"\n\n\"{threat._id}\" [ fillcolor=\"#F8CECC\", style=filled, shape=polygon, color=\"{CUSTOM_RED}\"")
    buf.append("    label= ")
    buf.append("    <<table border=\"0\" cellborder=\"0\" cellspacing=\"0\" width=\"505\">")
    buf.append(f"     <tr><td align=\"center\"><b>{_wrap_text(getattr(threat,'title', threat._id))}</b> <br/></td></tr>")
    buf.append(f"     <tr><td align=\"center\">{_wrap_text(getattr(threat,'attack',''))}</td></tr>")
    buf.append("   </table>>")
    buf.append("   ];")

    # Countermeasures
    for i, cm in enumerate(getattr(threat, 'countermeasures', []) or []):
        if not getattr(cm, 'description', None):
            continue
        try:
            colors = cm.statusColors()
            fill = colors.get('fill', '#FFFFFF')
            border = colors.get('border', '#000000')
        except Exception:  # pragma: no cover
            fill = '#FFFFFF'
            border = '#000000'
        buf.append(f"\n    \"{threat._id}_countermeasure{i}\" [ ")
        buf.append(f"       fillcolor=\"{fill}\", style=filled, shape=polygon, color=\"{border}\", label =     ")
        buf.append("    <<table border=\"0\" cellborder=\"0\" cellspacing=\"0\" width=\"505\">")
        cm_title = _wrap_text(getattr(cm, 'title', cm._id))
        cm_desc = _wrap_text(getattr(cm, 'description', ''))
        buf.append(f"     <tr><td align=\"left\"><b> {cm_title} ({getattr(cm,'_id','')}) </b><br/><br/> {cm_desc} </td></tr>")
        buf.append("   </table>>")
        buf.append("   ]")
        buf.append("")
        buf.append(f"    \"{threat._id}_countermeasure{i}\" -> \"{threat._id}\" [label = \" mitigates\"]")
    return "\n".join(buf)


def _render_secobj_root_node(secObj):
    return f"\"{secObj._id}\" [fillcolor=\"#bae9ff\", style=filled shape=ellipse, color=\"#2bbcff\", label= \n    <<table border=\"0\" cellborder=\"0\" cellspacing=\"0\">\n     <tr><td align=\"center\"><b>{secObj._id}</b><br/>{_wrap_text(getattr(secObj,'description',''))}</td></tr>\n   </table>>]"


def _build_secobj_diagram(secObj):
    """Replicates secObjTreePlantUMLDiagram.mako for a single security objective."""
    try:
        tmo_root = secObj.getRoot()
    except Exception:
        # Fallback: assume attribute rootTM or parent chain
        tmo_root = getattr(secObj, 'rootTM', None) or secObj

    lines = ["@startuml", "digraph G {", 'rankdir="RL";', '  node [shape=plaintext, fontname="Arial" fontsize="12"];', "    "]
    lines.append(_render_secobj_root_node(secObj))

    # Iterate all threats in the (global) model and render those impacting this security objective
    for threat in tmo_root.getAllDown('threats'):
        for impacted in _impacted_secobjs(threat):
            # impacted may have id or _id attribute referencing secObj
            impacted_id = getattr(impacted, 'id', getattr(impacted, '_id', str(impacted)))
            if impacted_id == secObj.id or impacted_id == secObj._id:
                lines.append(_render_threat_block(threat))
                lines.append(f'    "{threat._id}" -> "{secObj._id}" [label = " impacts"]')
                break  # no need to scan further impacted objs for this threat

    lines.append("\n}\n")
    lines.append("@enduml")
    return "\n".join(lines)


def generate(tmo, outputDir):
    """Generate one PlantUML diagram per security objective including threats & countermeasures."""
    os.makedirs(outputDir, exist_ok=True)
    for secObj in getattr(tmo, 'securityObjectives', []) or []:
        try:
            content = _build_secobj_diagram(secObj)
        except Exception as e:  # pragma: no cover
            traceback.print_exc()
            content = f"@startuml\n' ERROR generating secObj diagram for {getattr(secObj,'_id','UNKNOWN')}: {e}\n@enduml"
        out_file_name = os.path.join(outputDir, secObj._id + '.puml')
        with open(out_file_name, 'w', encoding='utf-8') as f:
            f.write(content)
    # Recurse into child threat models
    for child in tmo.getDescendantsTM():
        generate(child, outputDir)

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
    generate(tmo, outputDir)

    return 

if __name__ == "__main__":
    main()