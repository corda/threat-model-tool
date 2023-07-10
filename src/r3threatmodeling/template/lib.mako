
<%! import html %>
<%! from r3threatmodeling.template_utils import mermaid_escape, getShortDescForMermaid, createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<%! from cvss import CVSS3 %>
<%! from datetime import datetime %>

<%def name="trueorFalseMark(value: Boolean)">
${"<span style=\"color:green;\">&#10004;</span>" if value else "&#10060;" } \
</%def>

<%def name="renderMermaidThreatTree(threat: Threat)">
<% MERMAID_AT_HEAD="""
flowchart BT

    classDef threat fill:#F8CECC,stroke:#B85450
    classDef attack fill:#F5F5F5,stroke:#666666
    classDef countermeasureIP fill:#D5E8D4,stroke:#82B366
    classDef countermeasureNIP fill:#FFF2CC,stroke:#D6B656  
    classDef default text-align:left
    """

%>

<!-- mermaid start. Do not delete this comment-->
```mermaid
${MERMAID_AT_HEAD}
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
```
<!-- mermaid end. comment needed to it covert to HTML-->
</%def>

<%def name="renderTextSecurityObjectivesTree(securityObjectives: [])">
<% subgraphName = "no" %>
% for so in securityObjectives:
  % if subgraphName != so.group:
## ${'end' if subgraphName != "no" else ''}
<% subgraphName = so.group %>
**${subgraphName}**

  % endif
  - **${so._id}**: ${so.title}
  ## %if so.contributesTo:

  ##     Contributes to:
  ## %endif
  ## % for i, rel_so in enumerate(so.contributesTo):
  ##   ${rel_so._id} ${',' if i != len(so.contributesTo) - 1 else ''}
  ## % endfor

% endfor
</%def>


<%def name="renderMermaidSecurityObjectivesTree(securityObjectives: [])">
<% MERMAID_AT_HEAD="""
%%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%

flowchart BT
    classDef threat fill:#F8CECC,stroke:#B85450
    classDef attack fill:#F5F5F5,stroke:#666666
    classDef secObjective fill:#D5E8D4,stroke:#82B366
    classDef countermeasureNIP fill:#FFF2CC,stroke:#D6B656  
    classDef default text-align:left
    """

%>

<!-- mermaid start. Do not delete this comment-->
```mermaid
${MERMAID_AT_HEAD}
<% subgraphName = "no" %>
% for so in securityObjectives:
  % if subgraphName != so.group:
${'end' if subgraphName != "no" else ''}
<% subgraphName = so.group %>
subgraph ${subgraphName}
  % endif
  ${so._id}["${so.title}"]:::secObjective
  % for rel_so in so.contributesTo:
    ${so._id} --contributes to-->   ${rel_so._id}
  % endfor
% endfor
end

```
<!-- mermaid end. comment needed to it covert to HTML-->
</%def>

<%def name="executiveSummary(tmo)">
${makeMarkdownLinkedHeader(2, "Executive Summary", skipTOC = False)}

## <% unmitigatedYesOperational = tmo.getThreatsByFullyMitigatedAndOperational(False, True)%>
<% unmitigatedNoOperatinoal = tmo.getThreatsByFullyMitigatedAndOperational(False, False)%> ##TODO change search to not fully mitigated threats (configure flag correctly on threats yaml)
## <% mitigated  = tmo.getThreatsByFullyMitigated (True)%>
## <% unmitigated  = tmo.getThreatsByFullyMitigated (False)%>
> This section contains an executive summary of the threats and thier mitigation status

%if len(unmitigatedNoOperatinoal) < 1:
  **No unmitigated threats without operational countermeasures were identified**
%else:
There are **${len(unmitigatedNoOperatinoal)}** unmitigated threats without proposed operational controls.<br/>

<div markdown="1">

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Always valid</th></tr>
% for i , threat in enumerate(unmitigatedNoOperatinoal):
<% title = "`("+threat._id + ")` " + threat.title %>\
<tr markdown="block">
</td><td>
<a href="#${createTitleAnchorHash(title)}">${threat.id}</a> 
% if  hasattr(threat, 'ticketLink'):
<br/>
<a href="${html.escape(threat.ticketLink)}"> Ticket link  </a> 
% else:
% endif
</td>
</td><td style="background-color: ${threat.getSmartScoreColor()}; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>${threat.getSmartScoreDesc()}</strong></span> </td>
</td><td  style="text-align: center ">
% if  hasattr(threat, 'conditional'):
No
% else:
Yes
% endif
</td>
</tr>
%endfor
</table>

% endif

</%def>

<%def name="threatsSummary(tmo)">
${makeMarkdownLinkedHeader(2, "Threats Summary", skipTOC = False)}

<% unmitigatedYesOperational = tmo.getThreatsByFullyMitigatedAndOperational(False, True)%>
<% unmitigatedNoOperational = tmo.getThreatsByFullyMitigatedAndOperational(False, False)%>
<% mitigated  = tmo.getThreatsByFullyMitigated (True)%>
<% unmitigated  = tmo.getThreatsByFullyMitigated (False)%>
> This section contains an executive summary of the threats and thier mitigation status

%if len(mitigated) < 1 and len(unmitigated) < 1:
  **No threat identified or listed **
%else:
There are a total of **${len(tmo.getAllDown('threats'))}** identified threats of which **${len(unmitigated)}** are not fully mitigated 
by default, and  **${len(unmitigatedNoOperational)}** are unmitigated without proposed operational controls.<br/>

<div markdown="1">

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Valid when (condition)</th><th>Fully mitigated</th><th>Has Operational <br/> coutnermeasures</th></tr>
% for i , threat in enumerate(unmitigated + mitigated):
<% title = "`("+threat._id + ")` " + threat.title %>\
<tr markdown="block">
</td><td>
<a href="#${createTitleAnchorHash(title)}">${threat.id}</a> 
% if  hasattr(threat, 'ticketLink'):
<br/>
<a href="${html.escape(threat.ticketLink)}"> Ticket link  </a> 
% else:
% endif
</td>
</td><td style="background-color: ${threat.getSmartScoreColor()}; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>${threat.getSmartScoreDesc()}</strong></span> </td>
</td><td>
% if  hasattr(threat, 'conditional'):
${threat.conditional}
% else:
Always valid
% endif
</td>

<td style="text-align: center ">${trueorFalseMark(threat.fullyMitigated)}</td>

<td style="text-align: center ">
% if threat.hasOperationalCountermeasures():
Yes \
% else:
No \
% endif
</td>

</tr>
%endfor
</table>

% endif

</%def>

<%def name="renderThreat(threat)">

## ${H2} Threat ID: ${threat._id}
## ${threat.threatDesc()}
<% title = "`("+threat._id + ")` " + threat.title %>
${makeMarkdownLinkedHeader(3, title)}
<a href=""></a>
<div style="text-align: center;">
${renderMermaidThreatTree(threat)}
</div>

<dl markdown="block">
% if hasattr(threat, "assets") and threat.assets:

<dt>Assets (IDs) involved in this threat:</dt>

% for asset in threat.assets:
<dd markdown="block"> - <code><a href="#${asset.id}">${asset._id}</a></code> - ${asset.title}</dd>
%if hasattr(asset, "icon"): 
<img src="${asset.icon}"/>\
%endif
% endfor

% endif

% if hasattr(threat, "attackers") and threat.attackers:
  <dt>Attackers/threat agents:</dt>

% for attacker in threat.attackers:
<dd markdown="block"> - <code><a href="#${attacker.id}">${attacker._id}</a></code>\
%if hasattr(attacker, "icon"): 
<img src="${asset.icon}"/>\
%endif
</dd>
% endfor
  
% endif

% if hasattr(threat, "conditional"):
  <dt>Threat condition:</dt><dd markdown="block">${threat.conditional}</dd>
% endif

<% H6 = "######" %>

<dt>Threat Description</dt><dd markdown="block">${threat.attack}</dd>
% if hasattr(threat, "impactDesc") or  hasattr(threat, "impactedSecObjs") :
<dt>Impact</dt><dd markdown="block">${threat.impact_desc}</dd>
% endif

% if threat.cvssObject:
<% cvssObject = threat.cvssObject%>
<dt>CVSS</dt>
<dd>

<strong>${cvssObject.getSmartScoreType()}:</strong> ${cvssObject.getSmartScoreDesc()} 
<br/>
<strong>Vector:</strong><code>${cvssObject.clean_vector()}</code>
## <table>
## <tr>
## <th><h6>${cvssObject.getSmartScoreType()}</h6></th><td>${cvssObject.getSmartScoreDesc()}</td>
## </tr><tr>
## <th><h6>Vector</h6></th><td><code>${cvssObject.clean_vector()}</code></td>
## </tr>
## </table>
</dd>
% endif
</dl>
% if hasattr(threat, "ticketLink"):
  <dt><strong>Ticket link:</strong><a href="${html.escape(threat.ticketLink)}"> ${html.escape(threat.ticketLink)}  </a> </dt><dd markdown="block">   </dd>
% endif
% if len(threat.countermeasures) > 0:
${makeMarkdownLinkedHeader(4, 'Counter-measures for `'+threat._id + '`', True )}
<dl markdown="block">
% for countermeasure in threat.countermeasures:
    ##  - ID: T3.C1
    ##     description: autoscale Kubernetes cluster partially mitigated mitigates 
    ##     inPlace: yes
    ##     public: true
    
% if not countermeasure.isReference :
**`${countermeasure._id}` ${countermeasure.title}**<br/>
% else:
**Reference to `${countermeasure.id}` ${countermeasure.title}**<br/>
% endif
<dd markdown="block">
${countermeasure.description}</dd>


##*Is this countermeasure implemented and in place?* ${ "Yes" if countermeasure.inPlace else "No" }
##*Is this countermeasure public and disclosable?* ${ "Yes" if countermeasure.public else "No" }
<dd markdown="block">
<strong>Countermeasure implemented?</strong> ${trueorFalseMark(countermeasure.inPlace)} \
 <strong>Public and disclosable?</strong> ${trueorFalseMark(countermeasure.public)} \
% if countermeasure.operational:
 <strong>Is operational?</strong>${ "<span style=\"color:green;\">&#10004;</span>"}
 %if hasattr(countermeasure, "operator"):
    (operated by ${countermeasure.operator})
 %endif
% endif
</dd>

% endfor
</dl>
% else:
*No countermeasure listed*
% endif
</%def>

<%def name="renderSecurityObjective(securityObjective: SecurityObjective)">

<dl markdown="block">
<dt>ID</dt><dd><code><a id="${securityObjective.id}">${securityObjective._id}</a></code></dd>
%if hasattr(securityObjective, "icon"): 
 <img src="${securityObjective.icon}"/><br/>
%endif
<dt markdown="block">Title</dt>
<dd markdown="block">${securityObjective.title}</dd>
<dt markdown="block">Description</dt>
<dd markdown="block">${securityObjective.description}</dd>
% if securityObjective.contributesTo:
% for secObjectiveContributed in securityObjective.contributesTo:
  <dt markdown="block"> Contributes to:</dt>
  <dd markdown="block">${secObjectiveContributed.contributedToMDText()}</dd>
% endfor
% endif
% if hasattr(securityObjective, "treeImage"):
**Attack tree**

<img src="${securityObjective.treeImage}"/>
% endif


</dl>
<hr/>
</%def>


<%def name="renderAttacker(attacker: Attacker)">
<% INDENT = "&nbsp;&nbsp;&nbsp;&nbsp;"%>
<a id="${attacker.id}"></a>
**`${attacker.id}`** (from ${attacker.parent.id} scope) <br>
<dl markdown="block">
<dt>Description:</dt><dd markdown="block">${attacker.description}</dd>
%if hasattr(attacker, "reference"): 
<% R=attacker.reference%>
<dt>Reference:</dt><dd>${R|h}</dd>
%endif
<dt>In Scope:</dt><dd>${"Yes" if attacker.inScope else "No"}</dd>
</dl>

%if hasattr(attacker, "icon"): 
<img src="${attacker.icon}"/>\
%endif
##${INDENT}**Description:** ${attacker.description}         
##${INDENT}**In scope:** ${attacker.inScope}
<hr/>

</%def>


<%def name="renderAsset(asset: Asset)">
<hr/>
<a id="${asset.id}"></a>
${makeMarkdownLinkedHeader(5, asset.title, skipTOC = True )}
<dl markdown="block">
<dt>ID</dt><dd><code>${asset._id}</code></dd>
%if hasattr(asset, "icon"): 
 <img src="${asset.icon}"/><br/>
%endif

<dt markdown="block">Description</dt>
<dd markdown="block">${asset.description}</dd>
%if hasattr(asset, "authentication"):
<dt>Authentication</dt>
<dd markdown="block">${asset.authentication}</dd>
%endif
<dt>Type:</dt><dd>${asset.type}</dd>
%if hasattr(asset, "specifies"):
<dt>Specifies, inherit analysis and attribute from:</dt>
<% specifiedAsset = tmo.getById(asset.specifies) %>
<dd markdown="block"> ${specifiedAsset.title}  (<a href="#${specifiedAsset.id}">${specifiedAsset._id}</a>) </dd>
%endif
<dt>In scope:</dt><dd>${asset.inScope}</dd>
</dl>
</%def>

<%def name="renderAssetTable(assets: [Assets])">
<table markdown="block">
<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>
%for asset in sorted(assets, key=lambda a: a.inScope, reverse=True):
<tr markdown="block"><td markdown="block">${asset.title}<br/><code><strong markdown="block">${asset._id}</code>
</td><td>${asset.type}</td>
</td><td>${"&#x2714;&#xFE0F;" if asset._inScope else "&#x274C;"}</td>
</tr>
%endfor
</table>


</%def>


<%def name="renderTMReportPart(tmo: ThreatModel, ancestorData: Boolean,  toc = False, summary=False)">
##namespace trick :(
<% lib = self %> 

<% PAGEBREAK = """<div class="pagebreak"></div>"""%>


##TITLE
${makeMarkdownLinkedHeader(1, tmo.title + ' Threat Model', skipTOC = False)}

% if hasattr(tmo, 'version'):
Version: ${tmo.version}
% endif 

%if toc:
Last update: ${datetime.now().strftime("%Y-%m-%d %H:%M:%S")} 
%endif

% if hasattr(tmo, 'authors'):
Authors: ${tmo.authors}
% endif 

% if toc:
${PAGEBREAK}
${makeMarkdownLinkedHeader(2, 'Table of contents', skipTOC = True)}
__TOC_PLACEHOLDER__
${PAGEBREAK}

% endif

% if summary:

${executiveSummary(tmo)}
${PAGEBREAK}
${threatsSummary(tmo)}
% endif
${makeMarkdownLinkedHeader(2, tmo.title +  ' - scope of analysis')}

${makeMarkdownLinkedHeader(3, 'Overview')}
${tmo.scope.description} 
##@James: removed 'fmt' description ... was it to fix multiline RFIs ?

%if hasattr(tmo.scope, "references"):
${makeMarkdownLinkedHeader(3, 'References')}
% for ref in tmo.scope.references:
- ${ref}
%endfor
%endif

${makeMarkdownLinkedHeader(3, 'Security Objectives')}

%if hasattr(tmo, "securityObjectives"):

  % if len(tmo.securityObjectives) == 0:
No Security Objectives defined in this scope
  % else:
  **Summary list:**
${renderTextSecurityObjectivesTree(tmo.securityObjectives)}
  **Diagram:**
${renderMermaidSecurityObjectivesTree(tmo.securityObjectives)}
  **Details:**
    % for securityObjective in tmo.securityObjectives:
${lib.renderSecurityObjective(securityObjective)}

    % endfor
  % endif

% if ancestorData and tmo.parent != None:
  % if len(tmo.parent.securityObjectives) == 0:
No other Security Objective inherited
  % else:
${makeMarkdownLinkedHeader(4, 'Security Objectives inherited from other threat models')}
    % for securityObjective in tmo.parent.securityObjectives:
${lib.renderSecurityObjective(securityObjective)}

    % endfor
  % endif
% endif ##ancestorData
%endif


% if len(tmo.getDescendants()) > 0:

  ${makeMarkdownLinkedHeader(3, 'Linked threat Models', skipTOC = False)}

% for ltm in tmo.getDescendants():
  - **${ltm.title}** (ID: ${ltm.id})
% endfor
% endif

%if hasattr(tmo.scope, "diagram"):
${makeMarkdownLinkedHeader(3, 'Diagrams')}
${tmo.scope.diagram}
%endif 



> **Note** This section contains the list of attackers, personas, roles and potential threat agents considered to be within the scope of analysis.
###  Defined in this threat model 

% if len(tmo.attackers) > 0:
## No attackers defined in this scope
## % else:
${PAGEBREAK}
${makeMarkdownLinkedHeader(3, 'Attackers')}
% for attacker in tmo.attackers:
${lib.renderAttacker(attacker)}

% endfor
% endif

% if ancestorData and tmo.parent != None:
% if len(tmo.parent.getAllAttackers()) > 0:
## No other attackers inherited
## % else:

${makeMarkdownLinkedHeader(3, 'Attackers inherited from other threat models')}

% for attacker in tmo.parent.getAllAttackers():
${lib.renderAttacker(attacker)}

% endfor
% endif
% endif ##ancestorData

%if len(tmo.assumptions) > 0:
${makeMarkdownLinkedHeader(3, 'Assumptions')}
% for assumption in tmo.assumptions:

<dl markdown="block">
<dt>${assumption._id}</dt><dd>${assumption.description} </dd>
</dl>

% endfor
% endif




${PAGEBREAK}
${makeMarkdownLinkedHeader(3, 'Assets')}

${makeMarkdownLinkedHeader(4, 'Summary Table')}

${lib.renderAssetTable(tmo.assets)}



${makeMarkdownLinkedHeader(4, 'Details')}

% for asset in tmo.assets:
${lib.renderAsset(asset)} 
% endfor



% if hasattr (tmo, 'analysis'):
${PAGEBREAK}
<hr>
${makeMarkdownLinkedHeader(2, tmo.title + ' Analysis')}

> **Note** This section documents the work performed to identify threats and thier mitigations.#
> It may contains notes from the analysis sessions.
> This analysis section may be omitted in future reports.

${tmo.analysis}  
% endif

${PAGEBREAK}
<hr>
${makeMarkdownLinkedHeader(2, tmo.title +' Threats')}

> **Note** This section contains the threat and mitigations identified during the analysis phase.

%if len(tmo.threats) < 1:
  **No threat identified or listed **
%else:

% for i , threat in enumerate(tmo.threats):
%if i > 1:
<hr>
%endif
${lib.renderThreat(threat)}

% if (i!=len(tmo.threats)-1):
${PAGEBREAK}
 % endif

 % endfor

% endif

${PAGEBREAK}

% if hasattr(tmo, 'history'):
**Release history**

 ${tmo.history}
% endif 

</%def>
