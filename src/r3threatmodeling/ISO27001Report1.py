#!/usr/bin/env python3

# from lib2to3.pygram import pattern_symbols
# from pathvalidate import sanitize_filename
import os
from tokenize import String
import sys
import argparse
import time
import logging
from io import StringIO

from .template_utils import makeMarkdownLinkedHeader
import traceback
import html

from .threatmodel_data import *
# from markdown import Markdown
from .template_utils import *



def list_of_dicts_to_dict_of_dicts(list_of_dicts, id_key="id"):
    """
    Transforms a list of dictionaries into a dictionary of dictionaries using dictionary comprehension.
    """
    return {item[id_key]: item for item in list_of_dicts if isinstance(item, dict) and id_key in item}

def render_summary(tmo: ThreatModel, ctx=None, headerLevel=1, text: StringIO = StringIO()):
    """
    Renders the ISO27001 summary table as an HTML table compatible with Markdown.
    """
    text.write(makeMarkdownLinkedHeader(headerLevel, "ISO27001 Summary", ctx))
    text.write("\n\n")

    text.write("""<table>
  <thead>
    <tr>
      <th>Control ID</th>
      <th>Description</th>
      <th>Threats</th>
    </tr>
  </thead>
  <tbody>
""")

    # Pre-calculate dictionaries needed for the summary table
    isoDict = list_of_dicts_to_dict_of_dicts(tmo.ISO27001Ref, id_key="ID")
    threats = tmo.getAllDown('threats')
    threats_by_iso_ref = {}
    threat : Threat
    for threat in threats:
        if hasattr(threat, 'compliance') and isinstance(threat.compliance, list):
            for compliance_item in threat.compliance:
                if isinstance(compliance_item, dict) and 'ISO27001' in compliance_item and isinstance(compliance_item['ISO27001'], list):
                    for iso_ref_item in compliance_item['ISO27001']:
                        if isinstance(iso_ref_item, dict) and 'ref' in iso_ref_item:
                            ref_string = iso_ref_item['ref']
                            # Extract the control ID (e.g., "A.5.1")
                            control_id = ref_string.split(' ')[0]
                            if control_id not in threats_by_iso_ref:
                                threats_by_iso_ref[control_id] = []
                            # Append the threat object only if not already present
                            if threat not in threats_by_iso_ref[control_id]:
                                threats_by_iso_ref[control_id].append(threat)

    # Generate the summary table rows
    # Sort controls by ID for consistent order
    sorted_control_ids = sorted(isoDict.keys())

    for control_id in sorted_control_ids:
        control = isoDict[control_id]
        description = control.get('description', 'N/A')
        related_threats = threats_by_iso_ref.get(control_id, [])

        # Create Markdown links for related threats (these work fine in HTML)
        threat_links = []
        if related_threats:
            # Create a nested table for threats, without headers
            threat_links_str = "<table><tbody>"
            th: Threat
            for th in related_threats:
                # Use the threat._id for the anchor link target
                threat_anchor = th._id
                
                # Get mitigation status and apply color styling
                is_mitigated = getattr(th, 'fullyMitigated', False)
                if is_mitigated:
                    mitigated_status_html = '<span style="color:green;">Mitigated</span>'
                else:
                    mitigated_status_html = '<span style="color:red;">Not fully mitigated</span>'
                    
                # Get CVSS score
                cvss_score = " Severity: N/A"
                # Use cvssObject attribute as defined in Threat class
                if hasattr(th, 'cvssObject') and th.cvssObject:
                    # Assuming CVSS has a method or property like 'baseScore' or 'getScore'
                    # Adjust based on the actual attribute/method name in your Cvss class
                    try:
                        # Get the CVSS score description and color
                        score_desc = th.cvssObject.getSmartScoreDesc()
                        score_color = th.cvssObject.getSmartScoreColor()
                        if score_desc is not None:
                            # Apply color using an HTML span tag
                            cvss_score = f'<span style="color:{score_color};">{score_desc}</span>'
                    except AttributeError:
                        # Handle cases where the score attribute/method doesn't exist or returns None
                        pass 
                        
                # Create a table row for the threat with ID, styled mitigation status, and CVSS score
                threat_links_str += (
                    f'<tr>'
                    f'<td><a href="#{threat_anchor}"><code>{th._id}</code></a></td>'
                    f'<td>{mitigated_status_html}</td>'
                    f'<td>{cvss_score}</td>'
                    f'</tr>'
                )
            threat_links_str += "</tbody></table>"
        else:
            threat_links_str = "None"

        # Escape potential HTML characters in the description
        safe_description = html.escape(description)

        text.write(f"    <tr>\n")
        text.write(f"      <td>{control_id}</td>\n")
        text.write(f"      <td>{safe_description}</td>\n")
        text.write(f"      <td>{threat_links_str}</td>\n") # Links are already HTML compatible
        text.write(f"    </tr>\n")

    text.write(f"  </tbody>\n")
    text.write(f"</table>\n\n") # Add a newline after the table definition
    return text.getvalue()


def renderISO27001Report(tmo: ThreatModel, ctx=None, headerLevel=1):

    text = StringIO()
    text.write(makeMarkdownLinkedHeader(headerLevel, f"ISO27001 Report for {tmo._id}\n", ctx))

    text.write(f"Generated on {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
    text.write(f"[TOC]\n\n")

    render_summary(tmo, ctx, headerLevel, text=text)

    text.write(f"# ISO27001 Controls\n\n")

    grouped_ids = tmo.get_ISO27001_grouped_ids()

    isoDict = list_of_dicts_to_dict_of_dicts(tmo.ISO27001Ref, id_key="ID")

    threats = tmo.getAllDown('threats')

    #threats by iso27001 ref
    threats_by_iso_ref = {}
    threat : Threat
    # Iterate through the threats
    for threat in threats:
        # Check if threat has compliance and ISO27001 sections
        if hasattr(threat, 'compliance') and isinstance(threat.compliance, list):
            for compliance_item in threat.compliance:
                if isinstance(compliance_item, dict) and 'ISO27001' in compliance_item and isinstance(compliance_item['ISO27001'], list):
                    # Iterate through the ISO27001 references
                    for iso_ref_item in compliance_item['ISO27001']:
                        if isinstance(iso_ref_item, dict) and 'ref' in iso_ref_item:
                            ref_string = iso_ref_item['ref']
                            # Extract the control ID (e.g., "A.5.1")
                            control_id = ref_string.split(' ')[0]

                            # Add the threat to the dictionary
                            if control_id not in threats_by_iso_ref:
                                threats_by_iso_ref[control_id] = []
                            # Append the threat object
                            if threat not in threats_by_iso_ref[control_id]:
                                threats_by_iso_ref[control_id].append(threat)



    for isoGroup in tmo.get_ISO27001_groups_titles():
        text.write(f"## {isoGroup}\n")
        controls = grouped_ids[isoGroup]
        for controlId in controls:
            control = isoDict[controlId]
            text.write(f"### Control {controlId}: {control['description']}\n")

            # text.write(f"{tmo.get_ISO27001_control(control).description}\n")
            text.write("\n")

            # TODO Add the related threats
            for threat in threats_by_iso_ref.get(controlId, []):
                renderThreat(threat, text, ctx, headerLevel=headerLevel + 2)
                # text.write(f"**Threat**: {threat.id}\n\n")
                # text.write(f" {threat.title}\n")
                # text.write("\n")

    



    return text.getvalue()


def main():

    CLI=argparse.ArgumentParser()

    CLI.add_argument(
        "--rootTMYaml",
        default = None,
        required=True,
        type=open
    )

    # CLI.add_argument(
    #     "--YAMLprefix",  
    #     default = "",
    #     required=False
    # )

    CLI.add_argument(
    "--outputDir", 
    default = "build/",
    required=False
    )

    args = CLI.parse_args()
 
    tmo = ThreatModel(args.rootTMYaml)
    outputDir = args.outputDir


    reportText = renderISO27001Report(tmo)

    # Ensure output directory exists
    os.makedirs(outputDir, exist_ok=True)

    # Construct the output file path
    output_filename = f"{tmo._id}_ISO27001_Report.md"
    output_filepath = os.path.join(outputDir, output_filename)

    # Write the report to the file
    try:
        with open(output_filepath, 'w', encoding='utf-8') as f:
            f.write(reportText)
        print(f"Report successfully written to {output_filepath}")
    except IOError as e:
        print(f"Error writing report to file {output_filepath}: {e}", file=sys.stderr)
        sys.exit(1)


    return 

def renderThreat(threat: Threat, text: StringIO, ctx=None, headerLevel=1):
    """
    Renders a single threat into the provided StringIO object using Python.
    Equivalent to the renderThreat Mako template function.
    """
    is_proposal = hasattr(threat, 'proposal')
    div_class = 'proposal' if is_proposal else 'current'

    text.write(f'<div markdown="1" class="{div_class}">\n\n')

    # # Anchor for linking
    # text.write(f'<a id="{threat._id}"></a>\n')
    # # The Mako template has commented-out H2 headers, skipping them.

    # # Main header using helper function
    title = f"Title: {threat.title} (<code>{threat._id}</code>)"
    text.write(makeMarkdownLinkedHeader(headerLevel + 1, title, ctx, tmObject=threat))
    text.write("\n\n")

    if is_proposal:
        text.write(f"From proposal: {threat.proposal}\n\n")

   
    # text.write('<div style="text-align: center;">\n')
    # text.write(f'  <img src="img/threatTree/{threat._id}.svg"/>\n')
    # text.write('</div>\n\n')


    text.write('<dl markdown="block">\n\n')

    if hasattr(threat, "appliesToVersions"):
        text.write('<dt>Applies To Versions</dt>\n')
        text.write(f'<dd markdown="block">{html.escape(threat.appliesToVersions)}</dd>\n')

    # if hasattr(threat, "assets") and threat.assets:
    #     text.write('<dt>Assets (IDs) involved in this threat:</dt>\n\n')
    #     for asset in threat.assets:
    #         # Assuming asset has an 'anchor' attribute generated similarly to how Mako might do it
    #         asset_anchor = getattr(asset, 'anchor', asset._id) # Fallback to _id if anchor missing
    #         text.write(f'<dd markdown="block"> - <code><a href="#{asset_anchor}">{asset._id}</a></code> - {asset.title}</dd>\n')
    #         if hasattr(asset, "icon"):
    #             text.write(f'<img src="{asset.icon}"/>\\\n')
    #     text.write("\n")


    # if hasattr(threat, "attackers") and threat.attackers:
    #     text.write('  <dt>Threat actors:</dt>\n\n')
    #     for attacker in threat.attackers:
    #          # Assuming attacker has an 'anchor' attribute
    #         attacker_anchor = getattr(attacker, 'anchor', attacker._id)
    #         text.write(f'<dd markdown="block"> - <code><a href="#{attacker_anchor}">{attacker._id}</a></code>\\\n')
    #         if hasattr(attacker, "icon"):
    #             # The mako template references asset.icon here, which seems like a bug. Assuming it should be attacker.icon
    #             text.write(f'<img src="{attacker.icon}"/>\\\n')
    #     text.write('</dd>\n') # Closing the dd for the last attacker
    #     text.write("\n")


    # if hasattr(threat, "conditional"):
    #     text.write(f'  <dt>Threat condition:</dt><dd markdown="block">{threat.conditional}</dd>\n')

    # text.write('<dt>Threat Description</dt>')
    # # Ensure attack description is treated as markdown block
    # text.write(f'<dd markdown="block">{threat.attack}</dd>\n')


    # # Use impact_desc property which combines impactDesc and impactedSecObjs
    # if hasattr(threat, "impact_desc") and threat.impact_desc:
    #      text.write('<dt>Impact</dt>')
    #      text.write(f'<dd markdown="block">{threat.impact_desc}</dd>\n')


    # if hasattr(threat, "attackType"): # Mako uses attackType, assuming it exists
    #     text.write('<dt>Attack type</dt>\n')
    #     text.write(f'<dd markdown="block">{threat.attackType}</dd>\n')


    if hasattr(threat, 'cvssObject') and threat.cvssObject:
        cvssObject = threat.cvssObject
        text.write('<dt>CVSS</dt>\n')
        text.write('<dd>\n\n') # Start dd

        text.write(f'<strong>{cvssObject.getSmartScoreType()}:</strong> {cvssObject.getSmartScoreDesc()} \n')
        text.write('<br/>\n')
        text.write(f'<strong>Vector:</strong><code>{cvssObject.clean_vector()}</code>\n')

        text.write('</dd>\n') # End dd


    # if hasattr(threat, "compliance") and threat.compliance:
    #     text.write('Compliance:\n\n') # Mako has this outside dt/dd
    #     # Assuming renderNestedMarkdownList exists and works correctly
    #     text.write(renderNestedMarkdownList(threat.compliance, -1, firstIndent=None))
    #     text.write("\n\n")
    #     # The Mako template has a commented-out block for compliance standards, skipping it.


    text.write('</dl>\n') # End of the main definition list

    if hasattr(threat, "ticketLink") and threat.ticketLink is not None:
        # Mako wraps this in dt/dd but it looks better outside the dl
        text.write(f'<strong>Ticket link:</strong><a href="{html.escape(threat.ticketLink)}"> {html.escape(threat.ticketLink)}</a>\n\n')

    if hasattr(threat, 'countermeasures') and len(threat.countermeasures) > 0:
        # Countermeasures header using helper function
        text.write(makeMarkdownLinkedHeader(headerLevel + 3, f'Counter-measures for {threat._id} ', ctx, True, tmObject=None))
        text.write("\n")
        text.write('<dl markdown="block">\n') # Start countermeasures dl

        for countermeasure in threat.countermeasures:
            text.write('\n') # Space between countermeasures
            if not getattr(countermeasure, 'isReference', False): # Check if it's a reference
                text.write(f'<strong> <code>{countermeasure._id}</code> {countermeasure.title}</strong><br/>\n')
            else:
                text.write(f'<strong>Reference to <code>{countermeasure.id}</code> {countermeasure.title}</strong><br/>\n')

            if hasattr(countermeasure, "appliesToVersions"):
                 text.write('<dt>Applies To Versions</dt>\n')
                 text.write(f'<dd markdown="block">{html.escape(countermeasure.appliesToVersions)}</dd>\n')

            # # Description
            # text.write('<dd markdown="block">\n')
            # text.write(f'{countermeasure.description}\n')
            # text.write('</dd>\n')

            # if hasattr(countermeasure, "mitigationType"):
            #      text.write('<dd markdown="block">')
            #      text.write(f'<strong>Mitigation type:</strong>{countermeasure.mitigationType}')
            #      text.write('</dd>\n')


            # InPlace, Public, Operational status
            text.write('<dd markdown="block">\n')
            text.write(f'<strong>Countermeasure implemented?</strong> {trueorFalseMark(countermeasure.inPlace)} \n ')
            text.write(f'<strong>Public and disclosable?</strong> {trueorFalseMark(countermeasure.public)} \n')
            if getattr(countermeasure, 'operational', False):
                text.write(f' <strong>Is operational?</strong>"<span style="color:green;">&#10004;</span>" \n') # Escaped quotes for f-string
                if hasattr(countermeasure, "operator"):
                    text.write(f'    (operated by {countermeasure.operator}) \n')
            text.write('</dd> \n\n') # End dd for status line

        text.write('</dl> \n') # End countermeasures dl
    else:
        text.write('<i>No countermeasure listed</i>\n')

    text.write('</div>\n\n') # End threat div


if __name__ == "__main__":
    main()



