from __future__ import annotations
import html, textwrap
from datetime import datetime
import html, textwrap
from typing import List, Iterable, Optional

# Reuse existing helpers from your project (explicit imports to avoid wildcard / linter issues)
from .template_utils import (
    is_heading_numbering_enabled,
    unmark,
    valueOr,
    makeMarkdownLinkedHeader,
    createObjectAnchorHash,
    renderNestedMarkdownList,
    enable_heading_numbering,
    disable_heading_numbering
)

# Domain type hints (lightweight; actual classes come from existing model)
class ThreatModel: ...
class Threat: ...
class Countermeasure: ...
class SecurityObjective: ...
class Attacker: ...
class Asset: ...

PAGEBREAK = "<div class=\"pagebreak\"></div>"

def wrap_text(input_str: str, columns: int = 80, str_size: int = 77 * 4) -> str:
    if len(input_str) >= str_size:
        input_str = input_str[:str_size] + "[...]"
    return "<br/>".join(textwrap.wrap(unmark(input_str), columns))

def true_or_false_mark(value: bool) -> str:
    return "<span style=\"color:green;\">&#10004;</span>" if value else "&#10060;"

# def render_threat_simple_block(threat) -> str:
#     """Return a simplified textual block (replacing previous diagram)."""
#     impact = valueOr(threat, "impact_desc", "(impact TBD)")
#     attack = getattr(threat, "attack", "(attack TBD)")
#     return (
#         # f"**Threat:** {threat.threatGeneratedTitle() if hasattr(threat,'threatGeneratedTitle') else threat.title}\n\n"
#         f"**Attack:** {attack}\n\n"
#         f"**Impact:** {impact}"
#     )

def render_text_security_objectives_tree(security_objectives: Iterable[SecurityObjective]) -> str:
    """Render grouped security objectives without spurious heading markers.

    Previously a literal '## end' was appended between groups which leaked into the
    generated markdown report as an unintended heading. We now just insert a blank
    line to visually separate groups.
    """
    out: List[str] = []
    current: Optional[str] = None
    for so in security_objectives:
        if current != so.group:
            if current is not None:
                # blank line to separate previous group from the next
                out.append("")
            current = so.group
            out.append(f"**{current}:**\n")
        out.append(f"- <a href=\"#{so.anchor}\">{so.title}</a>\n")
    return "\n".join(out)

def executive_summary(tmo: ThreatModel, header_level: int = 1, ctx=None) -> str:
    unmit_no_op = tmo.getThreatsByFullyMitigatedAndOperational(False, False)
    mitigated = tmo.getThreatsByFullyMitigated(True)
    unmitigated = tmo.getThreatsByFullyMitigated(False)
    lines = [
        makeMarkdownLinkedHeader(header_level + 1, "Executive Summary", ctx, skipTOC=False) ]
    
    lines.append("> This section contains an executive summary of the threats and their mitigation status.\n")

    if len(unmit_no_op) < 1:
        lines.append("**No unmitigated threats without operational countermeasures were identified**")
    else:

        lines.append(
            f"There are **{len(unmit_no_op)}** unmitigated threats without proposed operational controls.<br/>"
        )
        lines.append('<div markdown="1">')
        lines.append(
            "<table markdown=\"block\" style=\"print-color-adjust: exact; -webkit-print-color-adjust: exact;\">"
        )
        lines.append("<tr><th>Threat ID</th><th>CVSS</th><th>Always valid?</th></tr>")
        for threat in unmit_no_op:
            anchor = createObjectAnchorHash(threat)
            cvss_td = (
                f'<td style="background-color: {threat.getSmartScoreColor()}; " >'
                f' <span markdown="block" style="font-weight:bold; color:white;"><strong>{threat.getSmartScoreDesc()}</strong></span> </td>'
            )
            always = "No" if hasattr(threat, "conditional") else "Yes"
            lines.append(
                "<tr markdown=\"block\"><td>"
                f'<a href="#{anchor}">{threat.parent._id}.<br/>{threat._id}</a>'
                + (
                    "<br/><b>PROPOSAL (TBC) </b>"
                    if (hasattr(threat, "proposal") or hasattr(threat.threatModel, "proposal"))
                    else ""
                )
                + (
                    f'<br/><a href="{html.escape(threat.ticketLink)}"> Ticket link  </a>'
                    if getattr(threat, "ticketLink", None)
                    else ""
                )
                + f"</td>{cvss_td}<td  style=\"text-align: center \">{always}</td></tr>"
            )
        lines.append("</table>")
        lines.append("</div>")
    return "\n".join(lines)

def threats_summary(tmo: ThreatModel, header_level: int = 1, ctx=None) -> str:
    unmit_no_op = tmo.getThreatsByFullyMitigatedAndOperational(False, False)
    mitigated = tmo.getThreatsByFullyMitigated(True)
    unmit = tmo.getThreatsByFullyMitigated(False)
    all_count = len(tmo.getAllDown("threats"))
    lines = []
    lines.append(makeMarkdownLinkedHeader(header_level + 1, "Threats Summary", ctx, skipTOC=False))

    if len(mitigated) < 1 and len(unmit) < 1:
        lines.append("**No threat identified or listed **")
    else:
        lines.append(
            f"There are a total of **{all_count}** identified threats of which **{len(unmit)}** are not fully mitigated "
            f"by default, and  **{len(unmit_no_op)}** are unmitigated without proposed operational controls.<br/>"
        )
        lines.append('<div markdown="1">')
        lines.append(
            "<table markdown=\"block\" style=\"print-color-adjust: exact; -webkit-print-color-adjust: exact;\">"
        )
        lines.append(
            "<tr><th>Threat ID</th><th>CVSS</th><th>Valid when (condition)</th><th>Fully mitigated</th>"
            "<th>Has Operational <br/> countermeasures</th></tr>"
        )
        for threat in unmit + mitigated:
            anchor = createObjectAnchorHash(threat)
            cond = getattr(threat, "conditional", "Always valid")
            cvss_td = (
                f'<td style="background-color: {threat.getSmartScoreColor()}; " >'
                f'<span markdown="block" style="font-weight:bold; color:white;"><strong>{threat.getSmartScoreDesc()}</strong></span></td>'
            )
            fully = true_or_false_mark(threat.fullyMitigated)
            op = "Yes" if threat.hasOperationalCountermeasures() else "No"
            proposal = (
                "<br/><b>FROM PROPOSAL / TBC</b>"
                if (hasattr(threat, "proposal") or hasattr(threat.threatModel, "proposal"))
                else ""
            )
            ticket = (
                f'<br/><a href="{html.escape(threat.ticketLink)}"> Ticket link  </a>'
                if getattr(threat, "ticketLink", None)
                else ""
            )
            lines.append(
                "<tr markdown=\"block\"><td>"
                f'<a href="#{anchor}">{threat.parent._id}.<br/>{threat._id}</a>{proposal}{ticket}'
                f"</td>{cvss_td}<td>{cond}</td><td style=\"text-align: center \">{fully}</td>"
                f"<td style=\"text-align: center \">{op}</td></tr>"
            )
        lines.append("</table></div>")
    return "\n".join(lines)

def render_countermeasure(countermeasure) -> str:
    if countermeasure.isReference:
        header = f"<strong>Reference to <code>{countermeasure.id}</code> {countermeasure.title}</strong><br/>"
    else:
        header = f"<strong> <code>{countermeasure._id}</code> {countermeasure.title}</strong><br/>"
    lines = [header]
    if hasattr(countermeasure, "appliesToVersions"):
        lines.append(f"<dt>Applies To Versions</dt><dd markdown=\"block\">{html.escape(countermeasure.appliesToVersions)}</dd>")
    lines.append(f"<dd markdown=\"block\">{countermeasure.description}</dd>")
    if hasattr(countermeasure, "mitigationType"):
        lines.append(f"<dd markdown=\"block\"><strong>Mitigation type:</strong>{countermeasure.mitigationType}</dd>")
    ip = true_or_false_mark(countermeasure.inPlace)
    public = true_or_false_mark(countermeasure.public)
    
    if(countermeasure.parent.fullyMitigated and not countermeasure.inPlace):
        lines.append(f"<dd markdown=\"block\"><strong>Countermeasure in place?</strong> {ip} (not chosen as threat is mitigated by other countermeasures)</dd>")
    else:
        lines.append(f"<dd markdown=\"block\"><strong>Countermeasure in place?</strong> {ip}</dd>")

    # lines.append(f"<dd markdown=\"block\"><br/><strong>Disclosable?</strong> {public}") TODO: re-evluate if needed

    op = ""
    if getattr(countermeasure, "operational", False):
        op_mark = "<span style=\"color:green;\">&#10004;</span>"
        operator = f" (operated by {countermeasure.operator})" if hasattr(countermeasure, "operator") else ""
        op = f" <strong>Is operational?</strong>{op_mark}{operator}"
    lines.append(f"{op}</dd>")

    return "\n".join(lines)

def render_threat(threat, header_level: int = 1, ctx=None) -> str:
    """Render a threat block matching the Mako template (without mermaid diagram)."""
    lines: list[str] = []
    css_class = "proposal" if hasattr(threat, "proposal") else "current"
    lines.append(f"<div markdown=\"1\" class='{css_class}'>")
    # Anchor and legacy headings
    lines.append(f"<a id=\"{threat._id}\"></a>")
    if hasattr(threat, "threatDesc"):
        try:
            lines.append(f"## {threat.threatDesc()}")
        except Exception:
            pass
    title_with_code = f"{threat.title} (<code>{threat._id}</code>)"
    lines.append(makeMarkdownLinkedHeader(header_level + 2, title_with_code, ctx, tmObject=threat))
    if hasattr(threat, "proposal"):
        lines.append(f"From proposal: {threat.proposal}")
    # Centered static SVG (mermaid omitted by request)
    lines.append('<div style="text-align: center;">')
    lines.append(f'<img src="img/threatTree/{threat._id}.svg"/>')
    lines.append('</div>')
    # Definition list details
    lines.append("<dl markdown=\"block\">")
    if hasattr(threat, "appliesToVersions"):
        lines.append("<dt>Applies To Versions</dt>")
        lines.append(f"<dd markdown=\"block\">{html.escape(threat.appliesToVersions)}</dd>")
    if getattr(threat, "assets", []):
        lines.append("<dt>Assets (IDs) involved in this threat:</dt>")
        for asset in threat.assets:
            lines.append(
                f"<dd markdown=\"block\"> - <code><a href=\"#{asset.anchor}\">{asset._id}</a></code> - {asset.title}</dd>"
            )
    if getattr(threat, "attackers", []):
        lines.append("<dt>Threat actors:</dt>")
        for attacker in threat.attackers:
            lines.append(
                f"<dd markdown=\"block\"> - <code><a href=\"#{attacker.anchor}\">{attacker._id}</a></code></dd>"
            )
    status = 'Mitigated' if threat.fullyMitigated else 'Not fully mitigated'
    lines.append(f"<dt>Threat Status:</dt><dd markdown=\"block\">{status}</dd>")
    if hasattr(threat, "conditional"):
        lines.append(f"<dt>Threat condition:</dt><dd markdown=\"block\">{threat.conditional}</dd>")
    lines.append(f"<dt>Threat Description</dt><dd markdown=\"block\">{getattr(threat, 'attack', '')}</dd>")
    if hasattr(threat, "impact_desc"):
        lines.append(f"<dt>Impact</dt><dd markdown=\"block\">{threat.impact_desc}</dd>")
    if hasattr(threat, "attackType"):
        lines.append("<dt>Attack type</dt>")
        lines.append(f"<dd markdown=\"block\">{threat.attackType}</dd>")
    if threat.cvssObject:
        cvss = threat.cvssObject
        lines.append("<dt>CVSS</dt>")
        lines.append(
            "<dd>\n"
            f"<strong>{cvss.getSmartScoreType()}:</strong> {cvss.getSmartScoreDesc()} <br/>\n"
            f"<strong>Vector:</strong><code>{cvss.clean_vector()}</code>\n"
            "</dd>"
        )
    if hasattr(threat, "compliance"):
        lines.append(
            "Compliance:\n" + renderNestedMarkdownList(threat.compliance, -1, firstIndent=None)
        )
    lines.append("</dl>")
    if getattr(threat, "ticketLink", None):
        safe = html.escape(threat.ticketLink)
        lines.append(
            f"<dt><strong>Ticket link:</strong><a href=\"{safe}\"> {safe}  </a> </dt><dd markdown=\"block\"></dd>"
        )
    cms = getattr(threat, "countermeasures", [])
    if cms:
        lines.append(
            makeMarkdownLinkedHeader(
                header_level + 3, f"Counter-measures for {threat._id} ", ctx, True
            )
        )
        lines.append("<dl markdown=\"block\">")
        for cm in cms:
            lines.append(render_countermeasure(cm))
        lines.append("</dl>")
    else:
        lines.append("<i>No countermeasure listed</i>")
    lines.append("</div>")
    return "\n".join(lines)

def render_security_objective(so: SecurityObjective, header_level: int = 1, ctx=None) -> str:
    title = f"{so.title} (<code>{so._id}</code>)"
    lines = [makeMarkdownLinkedHeader(header_level + 3, title, ctx, tmObject=so)]
    if hasattr(so, "proposal"):
        lines.append(f"From proposal: {so.proposal}<br/>")
    if getattr(so, "inScope", True) is False:
        lines.append("(Not in scope)<br/>")
    if hasattr(so, "icon"):
        lines.append(f"<img src=\"{so.icon}\"/><br/>")
    lines.append(so.description)
    lines.append(f"**Priority:** {so.priority}\n")
    if getattr(so, "contributesTo", []):
        lines.append("**Contributes to:**\n")
        for c in so.contributesTo:
            lines.append(f"- {c.contributedToMDText()}\n")
    if getattr(so, "treeImage", False):
        lines.append("**Attack tree:**\n")
        lines.append(f"<img src=\"img/secObjectives/{so._id}.svg\"/>")
        lines.append("<img src=\"img/legend_SecObjTree.svg\" width=\"400\"/>")
    lines.append("<hr/>")
    return "\n".join(lines)

def render_attacker(attacker: Attacker, header_level: int = 1, ctx=None) -> str:
    title = f"{attacker.title} (<code>{attacker._id}</code>)"
    lines = [
        f"<a id=\"{attacker._id}\"></a>",
        makeMarkdownLinkedHeader(header_level + 4, title, ctx, skipTOC=True, tmObject=attacker),
        "<dl markdown=\"block\">",
        "<dt>Description:</dt><dd markdown=\"block\">"
        f"{attacker.description}</dd>",
    ]
    if hasattr(attacker, "reference"):
        lines.append(f"<dt>Reference:</dt><dd>{html.escape(attacker.reference)}</dd>")
    lines.append(f"<dt>In Scope as threat actor:</dt><dd>{'Yes' if attacker.inScope else 'No'}</dd>")
    lines.append("</dl>")
    if hasattr(attacker, "icon"):
        lines.append(f"<img src=\"{attacker.icon}\"/>")
    lines.append("<hr/>")
    return "\n".join(lines)

def render_asset(asset: Asset, header_level: int = 1, ctx=None, tmo: ThreatModel | None = None) -> str:
    css = "proposal" if hasattr(asset, "proposal") else "current"
    in_scope_str = "in scope" if asset.inScope else "not in scope"
    title = f"{asset.title} ({asset.type} {in_scope_str} - ID: <code>{asset._id}</code>)"
    lines = [f"<hr/>\n<div markdown=\"1\" class='{css}'>"]
    if hasattr(asset, "proposal"):
        lines.append(f"From proposal: {asset.proposal}")
    lines.append(f"<a id=\"{asset.id}\"></a>")
    lines.append(makeMarkdownLinkedHeader(header_level + 4, title, ctx, skipTOC=True, tmObject=asset))
    lines.append("<dl markdown=\"block\">")
    if hasattr(asset, "icon"):
        lines.append(f"<img src=\"{asset.icon}\"/><br/>")
    lines.append(asset.description)
    if hasattr(asset, "appliesToVersions"):
        lines.append("<dt>Applies To Versions</dt>")
        lines.append(f"<dd markdown=\"block\">{html.escape(asset.appliesToVersions)}</dd>")
    if hasattr(asset, "properties"):
        lines.append("<dt markdown=\"block\">Other properties</dt>")
        lines.append(f"<dd markdown=\"block\">{asset.propertiesHTML()}</dd>")
    if hasattr(asset, "authentication"):
        lines.append("<dt>Authentication</dt>")
        lines.append(f"<dd markdown=\"block\">{asset.authentication}</dd>")
    if hasattr(asset, "specifies"):
        if tmo:
            specified = tmo.getRoot().getDescendantById(asset.specifies)
            lines.append("<dt>Specifies, inherit analysis and attribute from:</dt>")
            lines.append(
                f"<dd markdown=\"block\"> {specified.title}  (<a href=\"#{specified.anchor}\">{specified._id}</a>) </dd>"
            )
    lines.append("</dl>\n</div>")
    return "\n".join(lines)

def render_asset_table(assets: Iterable[Asset]) -> str:
    lines = ["<table markdown=\"block\">", "<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>"]
    for a in sorted(assets, key=lambda x: x.inScope, reverse=True):
        check = "&#x2714;&#xFE0F;" if a._inScope else "&#x274C;"
        lines.append(
            f"<tr markdown=\"block\"><td markdown=\"block\">{a.title}<br/><code><strong markdown=\"block\">{a._id}</strong></code>"
            f"</td><td>{a.type}</td><td>{check}</td></tr>"
        )
    lines.append("</table>")
    return "\n".join(lines)

def render_tm_report_part(
    tmo: ThreatModel,
    ancestor_data: bool,
    toc: bool = False,
    summary: bool = False,
    header_level: int = 1,
    ctx=None,
) -> str:
    lines: List[str] = []
    
    defaultEnable_heading_numbering = is_heading_numbering_enabled()
    if defaultEnable_heading_numbering and tmo.isRoot():
        disable_heading_numbering()


    css = "proposal" if hasattr(tmo, "proposal") else "current"
    lines.append(f"<div markdown=\"block\" class='{css}'>")
    if hasattr(tmo, "proposal"):
        lines.append(f"From proposal: {tmo.proposal}\n")
    
    
    title = tmo.title + " Threat Model"
    if not tmo.isRoot():
        title = f"{title} Section"

    lines.append(makeMarkdownLinkedHeader(header_level, title, ctx, skipTOC=tmo.isRoot(), tmObject=tmo))
    
    if hasattr(tmo, "version"):
        lines.append(f"Version: {tmo.version}\n")
    if hasattr(tmo, "status"):
        lines.append(f"Status: {tmo.status}\n")
    if toc:
        lines.append(f"Last update: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    if hasattr(tmo, "authors"):
        lines.append(f"Authors: {tmo.authors}\n")
    if hasattr(tmo, "versionsFilterStr"):
        lines.append(f"Versions in scope: {tmo.versionsFilterStr}\n")
    if toc:
        lines.append(PAGEBREAK)
        lines.append(makeMarkdownLinkedHeader(header_level + 1, "Table of contents", ctx, skipTOC=True))
        lines.append("""<div markdown=\"1\">\n\n__TOC_PLACEHOLDER__\n\n</div>""")
        lines.append(PAGEBREAK)

    if defaultEnable_heading_numbering and tmo.isRoot():
        enable_heading_numbering()

    if summary:
        if toc:
            header_level = header_level - 1 # this to have a TOC numbering starting from here as 1. (after the title and the toc itself that skipTOC)
        lines.append(executive_summary(tmo, header_level, ctx))
        lines.append(PAGEBREAK)
        lines.append(threats_summary(tmo, header_level + 1 , ctx))
    # lines.append(PAGEBREAK)
    
    lines.append(makeMarkdownLinkedHeader(header_level + 1, tmo.title + " - scope of analysis", ctx))
    if hasattr(tmo.scope, "description") and tmo.scope.description:
        lines.append(makeMarkdownLinkedHeader(header_level + 2, tmo.title + " Overview", ctx))
        lines.append(tmo.scope.description)
    if hasattr(tmo.scope, "references"):
        lines.append(makeMarkdownLinkedHeader(header_level + 2, "References", ctx))
        for ref in tmo.scope.references:
            lines.append(f"- {ref}")
    # Security Objectives
    if hasattr(tmo, "securityObjectives"):
        if len(tmo.securityObjectives) > 0:
            lines.append(makeMarkdownLinkedHeader(header_level + 2, tmo.title + " security objectives", ctx))
            lines.append(render_text_security_objectives_tree(tmo.securityObjectives))
            if tmo.parent is None:
                lines.append("**Diagram:**\n<img src=\"img/secObjectives.svg\"/>")
            lines.append("**Details:**")
            for so in sorted(tmo.securityObjectives, key=lambda o: o.title):
                lines.append(render_security_objective(so, header_level, ctx))
    if ancestor_data and tmo.parent is not None:
        lines.append(makeMarkdownLinkedHeader(header_level + 2, "Security Objectives inherited from other threat models", ctx))
        if len(tmo.parent.securityObjectives) == 0:
            lines.append("No Security Objective inherited")
        else:
            for so in tmo.parent.securityObjectives:
                lines.append(render_security_objective(so, header_level, ctx))
    # Linked models
    descendants = tmo.getDescendantsTM()
    if len(descendants) > 0:
        lines.append(makeMarkdownLinkedHeader(header_level + 2, "Linked threat Models", ctx))
        for ltm in descendants:
            lines.append(f"- **{ltm.title}** (ID: {ltm.id})")
    # Diagrams
    if hasattr(tmo.scope, "diagram") and tmo.scope.diagram:
        lines.append(makeMarkdownLinkedHeader(header_level + 2, "Diagrams", ctx))
        lines.append(tmo.scope.diagram)
    # Attackers

    if len(tmo.attackers) > 0:
        lines.append(PAGEBREAK)
        lines.append(makeMarkdownLinkedHeader(header_level + 2, tmo.title + " Threat Actors", ctx))
        lines.append("> Actors, agents, users and attackers may be used as synonymous.\n")
        for attacker in tmo.attackers:
            lines.append(render_attacker(attacker, header_level, ctx))
    if ancestor_data and tmo.parent is not None and len(tmo.parent.getAllAttackers()) > 0:
        lines.append(makeMarkdownLinkedHeader(header_level + 2, "Actors inherited from other threat models", ctx))
        for attacker in tmo.parent.getAllAttackers():
            lines.append(render_attacker(attacker, header_level, ctx))
    # Assumptions
    if len(tmo.assumptions) > 0:
        lines.append(makeMarkdownLinkedHeader(header_level + 2, "Assumptions", ctx))
        for a in tmo.assumptions:
            lines.append(f"<dl markdown=\"block\"><dt>{a._id}</dt><dd>{a.description} </dd></dl>")
    # Assets
    if len(tmo.assets) > 0:
        # lines.append(PAGEBREAK)
        lines.append(makeMarkdownLinkedHeader(header_level + 2, "Assets", ctx))
        lines.append(makeMarkdownLinkedHeader(header_level + 3, "Summary Table", ctx))
        lines.append(render_asset_table(tmo.assets))
        lines.append(makeMarkdownLinkedHeader(header_level + 3, "Details", ctx))
        for asset in tmo.assets:
            lines.append(render_asset(asset, header_level, ctx, tmo))
    # Analysis
    if hasattr(tmo, "analysis") and tmo.analysis and len(tmo.analysis.strip()) > 5:
        # lines.append(PAGEBREAK)
        lines.append("<hr/>")
        lines.append(makeMarkdownLinkedHeader(header_level + 1, tmo.title + " Analysis", ctx))
        lines.append(tmo.analysis)
    # Threats
    if len(tmo.threats) > 0:
        # lines.append(PAGEBREAK)
        lines.append("<hr/>")
        lines.append(makeMarkdownLinkedHeader(header_level + 1, tmo.title + " Attack tree", ctx))
        lines.append(f'''<object type="image/svg+xml" style="width:100%; height:auto;" data="img/{tmo._id}_ATTACKTREE.svg">
                     <img src="img/{tmo._id}_ATTACKTREE.svg" alt="${tmo.title} attack tree" style="width:600; height:auto;" />
                     </object>''')
        lines.append('<img src="img/legend_AttackTree.svg" width="600"/>')
        lines.append(PAGEBREAK)
        lines.append("<hr/>")
        lines.append(makeMarkdownLinkedHeader(header_level + 1, tmo.title + " Threats", ctx))
        lines.append("\n> **Note** This section contains the threat and mitigations identified during the analysis phase.")
        for i, threat in enumerate(tmo.threats):
            if i > 1:
                lines.append("<hr/>")
            lines.append(render_threat(threat, header_level, ctx))
            if i != len(tmo.threats) - 1:
                lines.append(PAGEBREAK)
    lines.append(PAGEBREAK)
    if hasattr(tmo, "history"):
        lines.append("**Release history**")
        lines.append(tmo.history)
    lines.append("</div>")
    return "\n".join(lines)
