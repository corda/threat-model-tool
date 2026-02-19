#!/usr/bin/env python3

# from lib2to3.pygram import pattern_symbols
# from pathvalidate import sanitize_filename
import os
import argparse
import traceback
import textwrap
import html

from ..threatmodel_data import *
from .template_utils import clean_markdown_text



def _wrap_text(input_str: str, columns: int = 80, str_size: int = 77 * 4):
    """Replicates the wrapText() macro logic from the legacy Mako template.

    - Truncates overly long strings adding a trailing '[...]'
    - Wraps to given column width and joins lines with <br/>
    - Removes any markdown (simple best‑effort) because original used unmark()
    """

    # Clean markdown links and references
    input_str = clean_markdown_text(input_str)
    if input_str is None:
        return ""
    # Basic markdown removal (headers, emphasis) – keep simple to avoid heavy deps
    md_replacements = [("**", ""), ("__", ""), ("`", ""), ("*", ""), ("#", ""), ("_", ""), ("&", "")]
    for a, b in md_replacements:
        input_str = input_str.replace(a, b)
    if len(input_str) >= str_size:
        input_str = input_str[:str_size] + "[...]"
    wrapped = textwrap.wrap(input_str, columns)
    return "<br/>".join(wrapped) if wrapped else ""


def _countermeasure_colors(cm):
    # Expecting statusColors() method as in Mako template; provide fallback.
    try:
        colors = cm.statusColors()
        fill = colors.get('fill', '#FFFFFF')
        border = colors.get('border', '#000000')
    except Exception:  # pragma: no cover - defensive
        fill = '#FFFFFF'
        border = '#000000'
    return fill, border


def _sanitize(s: str) -> str:
    return html.escape(s or "")


def _secure_obj_list(threat):
    # The data model naming appears both as impactedSecObjs (object list) and impactedSecObj (YAML list).
    return getattr(threat, 'impactedSecObjs', None) or getattr(threat, 'impactedSecObj', []) or []


def _build_threat_puml(threat):
    threat_id = threat._id
    title = _sanitize(getattr(threat, 'title', threat_id))
    # impact_desc = _wrap_text(getattr(threat, 'impactDesc', '') or '')
    attack_text = _wrap_text(getattr(threat, 'attack', '') or '')
    sec_objs = _secure_obj_list(threat)

    lines = ["@startuml", "digraph G {", 'rankdir="BT";', '  node [shape=plaintext, fontname="Arial" fontsize="12"];']

    # Threat node
    lines.append(f'"{threat_id}" [ fillcolor="#F8CECC", style=filled, shape=polygon, color="#B85450"')
    lines.append('    label= ')
    lines.append('    <<table border="0" cellborder="0" cellspacing="0">')
    lines.append(f'     <tr><td align="center"><b>Threat</b><br/> {_wrap_text(title)}</td></tr>')
    # lines.append(f'     <tr><td align="center"><b>Impact</b><br/>{impact_desc}</td></tr>')
    if sec_objs:
        lines.append('     <tr><td><table border="0" cellborder="0" cellspacing="8"><tr>')
        for so in sec_objs:
            try:
                so_id = getattr(so, '_id', getattr(so, 'id', str(so)))
                so_href = getattr(so, 'id', so_id)
            except Exception:
                so_id = str(so)
                so_href = so_id
            lines.append(f'     <td align="center" href="#{so_href}" bgcolor="#EEEEEE"><font color="blue">{_sanitize(so_id)}</font></td>')
        lines.append('     </tr></table></td></tr>')
    lines.append('   </table>>')
    lines.append('   ];')
    lines.append('    ')

    # Attack node
    lines.append(f'"{threat_id}_attack" [ fillcolor="#f5f5f5", style=filled, shape=polygon, color="#666666", label =     ')
    lines.append('    <<table border="0" cellborder="0" cellspacing="0">')
    lines.append(f'     <tr><td align="center"><b>Attack</b><br/>{attack_text}</td></tr>')
    lines.append('   </table>>')
    lines.append('    ]')
    lines.append('')
    lines.append(f'"{threat_id}_attack" -> "{threat_id}"  [label = " exploits"]')
    lines.append('')

    # Countermeasures
    countermeasures = getattr(threat, 'countermeasures', []) or []
    if countermeasures:
        for i, cm in enumerate(countermeasures):
            desc = getattr(cm, 'description', None)
            if desc is None:
                continue
            raw_cm_title = getattr(cm, 'title', f'CM {i}')
            cm_title = _sanitize(_wrap_text(raw_cm_title))
            fill, border = _countermeasure_colors(cm)
            lines.append(f'"{threat_id}_countermeasure{i}" [ ')
            lines.append(f'       fillcolor="{fill}", style=filled, shape=polygon, color="{border}", label =     ')
            lines.append('    <<table border="0" cellborder="0" cellspacing="0">')
            lines.append(f'     <tr><td align="left"><b>Countermeasure</b><br/> {cm_title}</td></tr>')
            lines.append('   </table>>')
            lines.append('   ]')
            lines.append('')
            lines.append(f'     "{threat_id}_countermeasure{i}" -> "{threat_id}_attack" [label = " mitigates"]')
            lines.append('')

    lines.append('}')
    lines.append('@enduml')
    return "\n".join(lines)


def generate(tmo, outputDir):
    """Generate per-threat PlantUML diagrams (full feature parity with legacy Mako template)."""
    os.makedirs(outputDir, exist_ok=True)
    for threat in tmo.getAllDown("threats"):
        try:
            content = _build_threat_puml(threat)
        except Exception as e:  # pragma: no cover - produce minimal fallback to not halt build
            traceback.print_exc()
            content = f"@startuml\n' ERROR generating diagram for {getattr(threat,'_id','UNKNOWN')}: {e}\n@enduml"
        out_file_name = os.path.join(outputDir, threat._id + '.puml')
        with open(out_file_name, 'w', encoding='utf-8') as f:
            f.write(content)

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



