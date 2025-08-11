"""Pure Python renderers replacing former Mako templates.

Each function returns a markdown string equivalent to the previous
`*.mako` template output so the rest of the pipeline (TOC injection,
Markdown->HTML conversion, PDF generation) remains unchanged.

High-level mapping:
  TM_templateFull.mako              -> render_full_report()
  TM_templateMKDOCS.mako            -> render_mkdocs_report()
  TM_templateNoTocNoSummary.mako    -> render_compact_report()
  operationalHardeningGuide.mako    -> render_operational_hardening()
  testingGuide.mako                 -> render_testing_guide()
  keysSummary.mako + keyTable.mako  -> render_keys_summary()
  index_* / conf_*                  -> (handled separately in future step)

The lower-level building blocks already exist in lib_py (render_tm_report_part etc.).
"""
from __future__ import annotations
from typing import Iterable, List

from ..template_utils import makeMarkdownLinkedHeader
from .lib_py import (
    render_tm_report_part,
    PAGEBREAK,
)

# Type hints (lightweight forward declarations; real classes provided elsewhere)
class ThreatModel: ...
class Countermeasure: ...
class Asset: ...


def _flatten_operational_countermeasures(tmo: ThreatModel) -> List[Countermeasure]:
    """Collect and return all operational countermeasures sorted by ID.

    Equivalent logic to operationalHardeningGuide.mako.
    """
    all_operational = []
    try:
        data = tmo.getOperationalGuideData()  # expected: { operator: [cm, ...], ... }
        for operator, cms in sorted(data.items()):
            all_operational.extend(cms)
    except Exception:
        return []
    return sorted(all_operational, key=lambda c: getattr(c, "_id", getattr(c, "id", "")))


def render_operational_hardening(tmo: ThreatModel, ctx=None, header_level: int = 1, print_toc: bool = False) -> str:
    cms = _flatten_operational_countermeasures(tmo)
    lines = [makeMarkdownLinkedHeader(header_level, "Operational Security Hardening Guide", ctx, skipTOC=False)]
    if print_toc:
        lines.append("__TOC_PLACEHOLDER__")
    lines.append(
        '<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">\n'
        "  <thead><tr><th>Seq</th><th>Countermeasure Details</th></tr></thead>\n  <tbody markdown=\"block\">"
    )
    for i, cm in enumerate(cms):
        parent = getattr(cm, "parent", None)
        parent_anchor = getattr(parent, "anchor", "") if parent else ""
        parent_title = getattr(parent, "title", "") if parent else ""
        parent_id = getattr(parent, "_id", "") if parent else ""
        cond = getattr(parent, "conditional", None)
        op_line = ""
        operator = getattr(cm, "operator", None)
        if operator and operator != "UNDEFINED":
            op_line = f"**Operated by:** {operator}<br/>"
        cond_line = f"**Valid when:** {cond}<br/>" if cond else ""
        lines.append(
            f"<tr markdown=\"block\"><td>{i+1}</td><td markdown=\"block\">**Title (ID):** {cm.title} (`{cm._id}`)<br/>\n"
            f"**Mitigates:** <a href=\"#{parent_anchor}\">{parent_title}</a> (`{parent_id}`)<br/><br/>\n"
            f"**Description:**\n{cond_line}{cm.description}\n<br/>{op_line}</td></tr>"
        )
    lines.append("</tbody></table>")
    return "\n".join(lines)


def _render_key_table(assets: Iterable[Asset]) -> str:
    lines = [
        '<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">',
        "  <tr><th>Title (ID)</th><th>Description</th><th>Properties</th></tr>",
    ]
    for a in assets:
        type_val = getattr(a, "type", "")
        if hasattr(a, "properties") and a.properties and "type" in a.properties:
            type_val = a.properties["type"]
        lines.append(
            f"  <tr><td><strong><a href=\"#{a.id}\">{a.title}</a></strong></td>"
            f"<td><b>{type_val}</b><br/>{a.description}</td><td>{a.propertiesHTML()}</td></tr>"
        )
    lines.append("</table>")
    return "\n".join(lines)


def render_keys_summary(tmo: ThreatModel, ctx=None, header_level: int = 1, print_toc: bool = False) -> str:
    lines = [makeMarkdownLinkedHeader(header_level, "Keys classification ", ctx, skipTOC=False)]
    if print_toc:
        lines.append("__TOC_PLACEHOLDER__")
    get_assets = getattr(tmo, "getAssetsByProps", None)
    if not get_assets:
        return "\n".join(lines)
    app_keys = get_assets(applicationRelated=True, type="key")
    if app_keys:
        lines.append(makeMarkdownLinkedHeader(header_level + 1, "Application-specific keys", ctx, skipTOC=False))
        lines.append("Keys issued to processes to communicate in a secure manner, not linked to a specific business logic")
        lines.append(_render_key_table(app_keys))
    infra_keys = get_assets(infrastructureRelated=True, type="key")
    certs = get_assets(type="certificate")
    if infra_keys or certs:
        lines.append(makeMarkdownLinkedHeader(header_level + 1, "Infrastructure Keys and PKI assets", ctx, skipTOC=False))
        lines.append(_render_key_table(infra_keys))
        lines.append(_render_key_table(certs))
    creds = get_assets(type="credential") + get_assets(type="credentials") + get_assets(type="secret")
    if creds:
        lines.append(makeMarkdownLinkedHeader(header_level + 1, "Credentials", ctx, skipTOC=False))
        lines.append(_render_key_table(creds))
    return "\n".join(lines)


def render_testing_guide(tmo: ThreatModel, ctx=None, header_level: int = 1, print_toc: bool = False) -> str:
    lines = [makeMarkdownLinkedHeader(header_level, "Testing guide", ctx, skipTOC=False)]
    lines.append("\nThis guide lists all testable attacks described in the threat model\n")
    testable = [t for t in tmo.getAllDown("threats") if getattr(t, "pentestTestable", False)]
    lines.append('<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">')
    lines.append("<tr><th>Seq</th><th>Attack to test</th><th>Pass/Fail/NA</th></tr>")
    for idx, threat in enumerate(testable):
        cond_line = f"\\n**Valid when:** {threat.conditional}" if hasattr(threat, "conditional") else ""
        lines.append(
            f"<tr markdown=\"block\"><td>{idx+1}</td><td markdown=\"block\">"
            f"<a href=\"#{threat.id}\">{threat.title}</a><br/>**Attack description:** {threat.attack}{cond_line}</td><td></td></tr>"
        )
    lines.append("</table>")
    return "\n".join(lines)


def render_full_report(
    tmo: ThreatModel,
    ctx=None,
    ancestor_data: bool = True,
    header_level: int = 1,
) -> str:
    lines = []
    lines.append(render_tm_report_part(tmo, ancestor_data, toc=True, summary=True, header_level=header_level, ctx=ctx))
    for descendant in tmo.getDescendantsTM():
        lines.append(render_tm_report_part(descendant, ancestor_data=False, header_level=header_level, ctx=ctx))
    lines.append(PAGEBREAK)
    lines.append(makeMarkdownLinkedHeader(header_level + 1, "Annex 1 Operational Hardening", ctx))
    lines.append(render_operational_hardening(tmo, ctx, header_level=header_level + 1, print_toc=False))
    lines.append(PAGEBREAK)
    lines.append(makeMarkdownLinkedHeader(header_level + 1, "Annex 2: Key Summary", ctx))
    lines.append(render_keys_summary(tmo, ctx, header_level=header_level + 1, print_toc=False))
    if hasattr(tmo, "ISO27001Ref") and getattr(tmo, "ISO27001Ref"):
        from r3threatmodeling.ISO27001Report1 import render_summary  # local import to avoid cycles
        lines.append(PAGEBREAK)
        # Keep ISO report aligned one level deeper than base annex heading
        lines.append(render_summary(tmo, ctx, headerLevel=header_level + 1))
    return "\n".join(lines)

def render_mkdocs_report(
    tmo: ThreatModel,
    ctx=None,
    ancestor_data: bool = True,
    header_level: int = 1,
) -> str:
    lines = []
    lines.append(render_tm_report_part(tmo, ancestor_data, toc=False, summary=True, header_level=header_level, ctx=ctx))
    for descendant in tmo.getDescendantsTM():
        # Descendants keep same base level for consistency (adjust if nesting desired)
        lines.append(render_tm_report_part(descendant, ancestor_data=False, header_level=header_level, ctx=ctx))
    lines.append(makeMarkdownLinkedHeader(header_level + 1, "Requests For Information", ctx))
    lines.append("__RFI_PLACEHOLDER__")
    lines.append(PAGEBREAK)
    lines.append(render_operational_hardening(tmo, ctx, header_level=header_level + 1, print_toc=False))
    lines.append(PAGEBREAK)
    lines.append(render_testing_guide(tmo, ctx, header_level=header_level + 1, print_toc=False))
    lines.append(PAGEBREAK)
    lines.append(render_keys_summary(tmo, ctx, header_level=header_level + 1, print_toc=False))
    if hasattr(tmo, "ISO27001Ref") and getattr(tmo, "ISO27001Ref"):
        from r3threatmodeling.ISO27001Report1 import render_summary
        lines.append(PAGEBREAK)
        lines.append(render_summary(tmo, ctx, headerLevel=header_level + 1))
    return "\n".join(lines)

def render_compact_report(
    tmo: ThreatModel,
    ctx=None,
    ancestor_data: bool = True,
    header_level: int = 1,
) -> str:
    lines = []
    lines.append(render_tm_report_part(tmo, ancestor_data, toc=False, summary=False, header_level=header_level, ctx=ctx))
    for descendant in tmo.getDescendantsTM():
        lines.append(render_tm_report_part(descendant, ancestor_data=False, header_level=header_level, ctx=ctx))
    lines.append(PAGEBREAK)
    lines.append(makeMarkdownLinkedHeader(header_level + 1, "Annex 1: Keys Summary", ctx))
    lines.append(render_keys_summary(tmo, ctx, header_level=header_level + 1, print_toc=False))
    return "\n".join(lines)

TEMPLATE_MAPPING = {
    "TM_templateFull": render_full_report,
    "TM_templateMKDOCS": render_mkdocs_report,
    "TM_templateNoTocNoSummary": render_compact_report,
    # backward compatibility alias
    "TM_template": render_full_report,
}


def render_template_by_name(name: str, tmo: ThreatModel, ancestor_data: bool, ctx=None, header_level: int = 1) -> str:
    func = TEMPLATE_MAPPING.get(name)
    if not func:
        raise ValueError(f"Unknown template name (Python renderer): {name}")
    # All mapped functions now share a header_level param for consistent nesting control
    return func(tmo, ctx=ctx, ancestor_data=ancestor_data, header_level=header_level)
