<%! import html %>
<%! import textwrap %>\
<%! from r3threatmodeling.template_utils import unmark, mermaid_escape, getShortDescForMermaid, createTitleAnchorHash, createObjectAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr, renderNestedMarkdownList  %>

<%! from cvss import CVSS3 %>
<%! from datetime import datetime %>


<%def name="wrapText(inputStr, columns=80, strSize=77*4)">
<%
if len(inputStr) >= strSize:
  inputStr = inputStr[:strSize]+ "[...]"
outputStr = "<br/>".join(textwrap.wrap(unmark(inputStr), columns))
%>
${outputStr}
</%def> 

<%def name="trueorFalseMark(value: Boolean)">
${"<span style=\"color:green;\">&#10004;</span>" if value else "&#10060;" } \
</%def>

<%def name="renderMermaidThreatTree(threat: Threatm, markdown=True)">
<% MERMAID_AT_HEAD="""
flowchart BT

    classDef threat fill:#F8CECC,stroke:#B85450
    classDef attack fill:#F5F5F5,stroke:#666666
    classDef countermeasureIP fill:#D5E8D4,stroke:#82B366
    classDef countermeasureNIP fill:#FFF2CC,stroke:#D6B656  
    classDef default text-align:left
    """

%>
% if markdown: 
<!-- mermaid start. Do not delete this comment-->
```mermaid
% endif
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
% if markdown: 
```
<!-- mermaid end. comment needed to it covert to HTML-->
% endif
</%def>

<%def name="renderTextSecurityObjectivesTree(securityObjectives: [])">
<% subgraphName = "no" %>
% for so in securityObjectives:
  % if subgraphName != so.group:
## ${'end' if subgraphName != "no" else ''}
<% subgraphName = so.group %>
**${subgraphName}:**

  % endif
  - <a href="#${so.anchor}">${so.title}</a>

  ## %if so.contributesTo:

  ##     Contributes to:
  ## %endif
  ## % for i, rel_so in enumerate(so.contributesTo):
  ##   ${rel_so._id} ${',' if i != len(so.contributesTo) - 1 else ''}
  ## % endfor

% endfor
</%def>


## <%def name="renderMermaidSecurityObjectivesTree(securityObjectives: [])">
## <% MERMAID_AT_HEAD="""
## %%{init: {"flowchart": {"defaultRenderer": "elk"}} }%%

## flowchart BT
##     classDef threat fill:#F8CECC,stroke:#B85450
##     classDef attack fill:#F5F5F5,stroke:#666666
##     classDef secObjective fill:#D5E8D4,stroke:#82B366
##     classDef countermeasureNIP fill:#FFF2CC,stroke:#D6B656  
##     classDef default text-align:left
##     """

## %>

## <!-- mermaid start. Do not delete this comment-->
## ```mermaid
## ${MERMAID_AT_HEAD}
## <% subgraphName = "no" %>
## % for so in securityObjectives:
##   % if subgraphName != so.group:
## ${'end' if subgraphName != "no" else ''}
## <% subgraphName = so.group %>
## subgraph ${subgraphName}
##   % endif
##   ${so._id}["${so.title}"]:::secObjective
##   % for rel_so in so.contributesTo:
##     ${so._id} --contributes to-->   ${rel_so._id}
##   % endfor
## % endfor
## end

## ```
## <!-- mermaid end. comment needed to it covert to HTML-->
## </%def>

<%def name="executiveSummary(tmo, headerLevel=1)">
${makeMarkdownLinkedHeader(headerLevel+1, "Executive Summary", ctx, skipTOC = False)}

## <% unmitigatedYesOperational = tmo.getThreatsByFullyMitigatedAndOperational(False, True)%>
<% unmitigatedNoOperatinoal = tmo.getThreatsByFullyMitigatedAndOperational(False, False)%>
## <% mitigated  = tmo.getThreatsByFullyMitigated (True)%>
## <% unmitigated  = tmo.getThreatsByFullyMitigated (False)%>
> This section contains an executive summary of the identified threats and their mitigation status

%if len(unmitigatedNoOperatinoal) < 1:
  **No unmitigated threats without operational countermeasures were identified**
%else:
There are **${len(unmitigatedNoOperatinoal)}** unmitigated threats without proposed operational controls.<br/>

<div markdown="1">

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Always valid?</th></tr>
% for i , threat in enumerate(unmitigatedNoOperatinoal):
<% title = "`("+threat._id + ")` " + threat.title %>\
<tr markdown="block"><td>
<a href="#${createObjectAnchorHash(threat)}">${threat.parent._id}.<br/>${threat._id}</a> 
% if  hasattr(threat, 'proposal') or hasattr(threat.threatModel, 'proposal'):
<br/>
<b>PROPOSAL (TBC) </b> 
% else:
% endif
% if hasattr(threat, 'ticketLink') and threat.ticketLink is not None:
<br/>
<a href="${html.escape(threat.ticketLink)}"> Ticket link  </a> 
##   % if hasattr(threat, 'ticketInfo'):
## ${ticketInfo}
##   % endif
% else:
% endif
</td><td style="background-color: ${threat.getSmartScoreColor()}; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>${threat.getSmartScoreDesc()}</strong></span> </td>
<td  style="text-align: center ">
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
</div>
</%def>

<%def name="threatsSummary(tmo, headerLevel=1)">
${makeMarkdownLinkedHeader(headerLevel+1, "Threats Summary", ctx, skipTOC = False)}

<% unmitigatedYesOperational = tmo.getThreatsByFullyMitigatedAndOperational(False, True)%>
<% unmitigatedNoOperational = tmo.getThreatsByFullyMitigatedAndOperational(False, False)%>
<% mitigated  = tmo.getThreatsByFullyMitigated (True)%>
<% unmitigated  = tmo.getThreatsByFullyMitigated (False)%>
> This section contains an executive summary of the threats and their mitigation status

%if len(mitigated) < 1 and len(unmitigated) < 1:
  **No threat identified or listed **
%else:
There are a total of **${len(tmo.getAllDown('threats'))}** identified threats of which **${len(unmitigated)}** are not fully mitigated 
by default, and  **${len(unmitigatedNoOperational)}** are unmitigated without proposed operational controls.<br/>

<div markdown="1">

<table markdown="block" style="print-color-adjust: exact; -webkit-print-color-adjust: exact;">
<tr><th>Threat ID</th><th>CVSS</th><th>Valid when (condition)</th><th>Fully mitigated</th><th>Has Operational <br/> countermeasures</th></tr>
% for i , threat in enumerate(unmitigated + mitigated):
<% title = "`("+threat._id + ")` " + threat.title %>\
<tr markdown="block">
<td>
<a href="#${createObjectAnchorHash(threat)}">${threat.parent._id}.<br/>${threat._id}</a> 
% if  hasattr(threat, 'proposal') or hasattr(threat.threatModel, 'proposal'):
<br/>
<b>FROM PROPOSAL / TBC</b> 
% else:
% endif

% if  hasattr(threat, 'ticketLink') and threat.ticketLink is not None:
<br/>
<a href="${html.escape(threat.ticketLink)}"> Ticket link  </a> 
% else:
% endif
</td><td style="background-color: ${threat.getSmartScoreColor()}; " > <span markdown="block" style="font-weight:bold; color:white;"><strong>${threat.getSmartScoreDesc()}</strong></span> </td>
<td>
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
</div>

</%def>

<%def name="renderThreat(threat, headerLevel=1)">

<div markdown="1" ${"class='proposal'" if hasattr(threat, 'proposal') else "class='current'"}>


<a id="${threat._id}"></a>
## ${H2} Threat ID: ${threat._id}
## ${threat.threatDesc()}

<% title =  threat.title + " (<code>"+threat._id + "</code>)" %>

${makeMarkdownLinkedHeader(headerLevel+2, title, ctx, tmObject=threat)} 

${"From proposal: " + threat.proposal if hasattr(threat, 'proposal') else ""}

<div style="text-align: center;">

## ${renderMermaidThreatTree(threat)}
<img src="img/threatTree/${threat._id}.svg"/>

</div>



<dl markdown="block">

%if hasattr(threat, "appliesToVersions"):
<dt>Applies To Versions</dt>
<dd markdown="block">${html.escape(threat.appliesToVersions)}</dd>
%endif
% if hasattr(threat, "assets") and threat.assets:

<dt>Assets (IDs) involved in this threat:</dt>

% for asset in threat.assets:
<dd markdown="block"> - <code><a href="#${asset.anchor}">${asset._id}</a></code> - ${asset.title}</dd>
%if hasattr(asset, "icon"): 
<img src="${asset.icon}"/>\
%endif
% endfor

% endif

% if hasattr(threat, "attackers") and threat.attackers:
  <dt>Threat actors:</dt>

% for attacker in threat.attackers:
<dd markdown="block"> - <code><a href="#${attacker.anchor}">${attacker._id}</a></code>\
%if hasattr(attacker, "icon"): 
<img src="${asset.icon}"/>\
%endif
</dd>
% endfor
  
% endif

% if hasattr(threat, "conditional"):
  <dt>Threat condition:</dt><dd markdown="block">${threat.conditional}</dd>
% endif

<dt>Threat Description</dt><dd markdown="block">${threat.attack}</dd>
% if hasattr(threat, "impactDesc") or  hasattr(threat, "impactedSecObjs") :
<dt>Impact</dt><dd markdown="block">${threat.impact_desc}</dd>
% endif

%if hasattr(threat, "attackType"):
<dt>Attack type</dt>
<dd markdown="block">${threat.attackType}</dd>
%endif


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




% if hasattr(threat, "compliance"):
Compliance:

${renderNestedMarkdownList(threat.compliance, -1, firstIndent=None)}

## <dt>Compliance Standards</dt>
## <dd>
## % for standard in threat.compliance:
## % for std_name, controls in standard.items():
## <strong>${std_name}:</strong>
## <ul>
## % for control in controls:
## ## % if hasattr(control, "ref"):
## <li>${control['ref']}</li>
## % endfor
## </ul>
## % endfor
## % endfor
## </dd>
% endif


</dl>
% if hasattr(threat, "ticketLink") and threat.ticketLink is not None:
  <dt><strong>Ticket link:</strong><a href="${html.escape(threat.ticketLink)}"> ${html.escape(threat.ticketLink)}  </a> </dt><dd markdown="block">   </dd>
% endif
% if len(threat.countermeasures) > 0:
${makeMarkdownLinkedHeader(headerLevel+3, f'Counter-measures for {threat._id} ', ctx, True , tmObject=None)}
<dl markdown="block">
% for countermeasure in threat.countermeasures:
    ##  - ID: T3.C1
    ##     description: autoscale Kubernetes cluster partially mitigated mitigates 
    ##     inPlace: yes
    ##     public: true
    
% if not countermeasure.isReference :
<strong> <code>${countermeasure._id}</code> ${countermeasure.title}</strong><br/>
% else:
<strong>Reference to <code>${countermeasure.id}</code> ${countermeasure.title}</strong><br/>
% endif
% if hasattr(countermeasure, "appliesToVersions"):
<dt>Applies To Versions</dt>
<dd markdown="block">${html.escape(countermeasure.appliesToVersions)}</dd>
% endif
<dd markdown="block">
${countermeasure.description}</dd>

% if hasattr(countermeasure, "mitigationType"):
<dd markdown="block"><strong>Mitigation type:</strong>${countermeasure.mitigationType}</dd>
%endif


##*Is this countermeasure implemented and in place?* ${ "Yes" if countermeasure.inPlace else "No" }
##*Is this countermeasure public and disclosable?* ${ "Yes" if countermeasure.public else "No" }
<dd markdown="block">
<strong>Countermeasure in place?</strong> ${trueorFalseMark(countermeasure.inPlace)} \
 <strong>Public and disclosable?</strong> ${trueorFalseMark(countermeasure.public)} \
% if countermeasure.operational: 
 <strong>Is operational?</strong>${ "<span style=\"color:green;\">&#10004;</span>"} \
 % if hasattr(countermeasure, "operator"): 
    (operated by ${countermeasure.operator}) 
 % endif 
% endif 
</dd> \

% endfor
</dl> \
% else: 
<i>No countermeasure listed</i>
% endif 
## threat div end

</div>

</%def>

<%def name="renderSecurityObjective(securityObjective: SecurityObjective, headerLevel=1)">


<% title =  f"{securityObjective.title} (<code>{securityObjective._id}</code>)" %>

${makeMarkdownLinkedHeader(headerLevel+3, f"{title}", ctx, skipTOC = False, tmObject = securityObjective )} 
${"From proposal: " + securityObjective.proposal if hasattr(securityObjective, 'proposal') else ""}


%if securityObjective.inScope == False: 
 (Not in scope)
%endif

%if hasattr(securityObjective, "icon"): 
 <img src="${securityObjective.icon}"/><br/>
%endif


${securityObjective.description}
**Priority:** ${securityObjective.priority}

% if securityObjective.contributesTo:
**Contributes to:**


% for secObjectiveContributed in securityObjective.contributesTo:
  - ${secObjectiveContributed.contributedToMDText()}
% endfor
% endif
% if securityObjective.treeImage:

**Attack tree:**

<img src="img/secObjectives/${securityObjective._id}.svg"/>
<img src="img/legend_SecObjTree.svg" width="400"/>

% endif


<hr/>


</%def>


<%def name="renderAttacker(attacker: Attacker, headerLevel=1)">
<% INDENT = "&nbsp;&nbsp;&nbsp;&nbsp;"%>

## <a id="${attacker._id}"></a>

${makeMarkdownLinkedHeader(headerLevel+4, f"{attacker.title} (<code>{attacker._id}</code>)" , ctx, skipTOC = True, tmObject=attacker )} 

<dl markdown="block">
<dt>Description:</dt><dd markdown="block">${attacker.description}</dd>
%if hasattr(attacker, "reference"): 
<% R=attacker.reference%>
<dt>Reference:</dt><dd>${R|h}</dd>
%endif
<dt>In Scope as threat actor:</dt><dd>${"Yes" if attacker.inScope else "No"}</dd>
</dl>

%if hasattr(attacker, "icon"): 
<img src="${attacker.icon}"/>\
%endif
##${INDENT}**Description:** ${attacker.description}         
##${INDENT}**In scope:** ${attacker.inScope}
<hr/>

</%def>


<%def name="renderAsset(asset: Asset, headerLevel=1)">
<hr/>

<div markdown="1" ${"class='proposal'" if hasattr(asset, 'proposal') else "class='current'"}>

${"From proposal: " + asset.proposal if hasattr(asset, 'proposal') else ""}

<%
  inScopeStr = "not in scope"
  if asset.inScope:
    inScopeStr = "in scope"
%>

<a id="${asset.id}"></a>

${makeMarkdownLinkedHeader(headerLevel+4, 
f"{asset.title} ({asset.type} {inScopeStr} - ID: <code>{asset._id}</code>)", ctx, skipTOC = True , tmObject=asset)} 
<dl markdown="block">
%if hasattr(asset, "icon"): 
 <img src="${asset.icon}"/><br/>
%endif
${asset.description}
%if hasattr(asset, "appliesToVersions"):
<dt>Applies To Versions</dt>
<dd markdown="block">${html.escape(asset.appliesToVersions)}</dd>
%endif
% if hasattr(asset, 'properties'):
<dt markdown="block">Other properties</dt>
<dd markdown="block">
${asset.propertiesHTML()}
</dd>
% endif
%if hasattr(asset, "authentication"):
<dt>Authentication</dt>
<dd markdown="block">${asset.authentication}</dd>
%endif
%if hasattr(asset, "specifies"):
<dt>Specifies, inherit analysis and attribute from:</dt>
<% specifiedAsset = tmo.getRoot().getDescendantById(asset.specifies) %>
<dd markdown="block"> ${specifiedAsset.title}  (<a href="#${specifiedAsset.anchor}">${specifiedAsset._id}</a>) </dd>
%endif
</dl>

</div>

</%def>

<%def name="renderAssetTable(assets: [Assets])">
<table markdown="block">
<tr><th>Title(ID)</th><th>Type</th><th>In Scope</th></tr>
%for asset in sorted(assets, key=lambda a: a.inScope, reverse=True):
<tr markdown="block"><td markdown="block">${asset.title}<br/><code><strong markdown="block">${asset._id}</strong></code>
</td><td>${asset.type}</td>
<td>${"&#x2714;&#xFE0F;" if asset._inScope else "&#x274C;"}</td>
</tr>
%endfor
</table>


</%def>


<%def name="renderTMReportPart(tmo: ThreatModel, ancestorData: Boolean,  toc = False, summary=False, headerLevel=1)">
##namespace trick :(
<% lib = self %> 

<div markdown="block" ${"class='proposal'" if hasattr(tmo, 'proposal') else "class='current'"}>

${"From proposal: " + tmo.proposal if hasattr(tmo, 'proposal') else ""}


<% PAGEBREAK = """<div class="pagebreak"></div>"""%>


##TITLE
${makeMarkdownLinkedHeader(headerLevel, tmo.title, ctx, skipTOC = False, tmObject=tmo)}

% if hasattr(tmo, 'version'):
Version: ${tmo.version}
% endif 

% if hasattr(tmo, 'status'):
Status: ${tmo.status}
% endif 

%if toc:
Last update: ${datetime.now().strftime("%Y-%m-%d %H:%M:%S")} 
%endif

% if hasattr(tmo, 'authors'):
Authors: ${tmo.authors}
% endif 

% if hasattr(tmo, 'versionsFilterStr'):
Versions in scope: ${tmo.versionsFilterStr}
% endif 

% if toc:
${PAGEBREAK}
${makeMarkdownLinkedHeader(headerLevel+1, 'Table of contents', ctx, skipTOC = True)}
<div markdown="1">

## [TOC] use this to have a better TOC but will loose it in the MD format (TOC only in HTML)

__TOC_PLACEHOLDER__ ## this creates a TOC in the markdown file as well

</div>
${PAGEBREAK}
% endif

% if summary:

${executiveSummary(tmo)}
${PAGEBREAK}
${threatsSummary(tmo)}
% endif
${PAGEBREAK}
${makeMarkdownLinkedHeader(headerLevel+1, tmo.title +  ' - scope of analysis', ctx, tmObject=None)}

% if hasattr(tmo.scope, "description") and tmo.scope.description: 
${makeMarkdownLinkedHeader(headerLevel+2, 'Overview', ctx)}
${tmo.scope.description} 
% endif
##@James: removed 'fmt' description ... was it to fix multiline RFIs ?

%if hasattr(tmo.scope, "references"):
${makeMarkdownLinkedHeader(headerLevel+2, 'References', ctx)}
% for ref in tmo.scope.references:
- ${ref}
%endfor
%endif

% if hasattr(tmo, "securityObjectives"):
  % if len(tmo.securityObjectives) == 0:

## No Security Objectives defined in this scope
  % else:
${makeMarkdownLinkedHeader(headerLevel+2, tmo.title + ' security objectives', ctx)}

${renderTextSecurityObjectivesTree(tmo.securityObjectives)}
  **Diagram:**
  <img src="img/secObjectives.svg"/>
## ${renderMermaidSecurityObjectivesTree(tmo.securityObjectives)}
  **Details:**
    % for securityObjective in sorted(tmo.securityObjectives, key=lambda obj: obj.title):
${lib.renderSecurityObjective(securityObjective)}

    % endfor
  % endif
% endif ##secObj attr

  % if ancestorData and tmo.parent != None:  ##ancestorData
${makeMarkdownLinkedHeader(headerLevel+2, 'Security Objectives inherited from other threat models', ctx)}
    % if len(tmo.parent.securityObjectives) == 0:
No Security Objective inherited
  % else:
    % for securityObjective in tmo.parent.securityObjectives:
${lib.renderSecurityObjective(securityObjective)}

    % endfor
    % endif ## len(tmo.parent.securityObjectives) == 0:
  % endif ##ancestorData


% if len(tmo.getDescendantsTM()) > 0:

  ${makeMarkdownLinkedHeader(headerLevel+2, 'Linked threat Models', ctx, skipTOC = False)}

% for ltm in tmo.getDescendantsTM():
  - **${ltm.title}** (ID: ${ltm.id})
% endfor
% endif

%if hasattr(tmo.scope, "diagram") and tmo.scope.diagram:
${makeMarkdownLinkedHeader(headerLevel+2, 'Diagrams', ctx)}
${tmo.scope.diagram}
%endif 



## > **Note** This section contains the list of attackers, personas, roles and potential threat agents considered to be within the scope of analysis.
###  Defined in this threat model 

% if len(tmo.attackers) > 0:
## No actors defined in this scope
## % else:
${PAGEBREAK}
${makeMarkdownLinkedHeader(headerLevel+2, tmo.title + ' Threat Actors', ctx)}

> Actors, agents, users and attackers may be used as synonymous.

% for attacker in tmo.attackers:
${lib.renderAttacker(attacker)}

% endfor
% endif

% if ancestorData and tmo.parent != None:
% if len(tmo.parent.getAllAttackers()) > 0:
## No other actors inherited
## % else:

${makeMarkdownLinkedHeader(headerLevel+2, 'Actors inherited from other threat models', ctx)}

% for attacker in tmo.parent.getAllAttackers():
${lib.renderAttacker(attacker)}

% endfor
% endif
% endif ##ancestorData

%if len(tmo.assumptions) > 0:
${makeMarkdownLinkedHeader(headerLevel+2, 'Assumptions', ctx)}
% for assumption in tmo.assumptions:

<dl markdown="block">
<dt>${assumption._id}</dt><dd>${assumption.description} </dd>
</dl>

% endfor
% endif



% if len(tmo.assets) > 0:
${PAGEBREAK}
${makeMarkdownLinkedHeader(headerLevel+2, 'Assets', ctx)}

${makeMarkdownLinkedHeader(headerLevel+3, 'Summary Table', ctx)}

${lib.renderAssetTable(tmo.assets)}



${makeMarkdownLinkedHeader(headerLevel+3, 'Details', ctx)}

% for asset in tmo.assets:
${lib.renderAsset(asset)} 
% endfor

% endif

% if hasattr (tmo, 'analysis') and tmo.analysis and len(tmo.analysis.strip()) > 5: #something like TODO will be hidden 
${PAGEBREAK}
<hr/>
${makeMarkdownLinkedHeader(headerLevel+1, tmo.title + ' Analysis', ctx, tmObject=None)}

## > **Note** This section documents the work performed to identify threats and thier mitigations.#
## > It may contains notes from the analysis sessions.
## > This analysis section may be omitted in future reports.

${tmo.analysis}  
% endif

%if len(tmo.threats) > 0:

${PAGEBREAK}
<hr/>
${makeMarkdownLinkedHeader(headerLevel+1, tmo.title +' Attack tree', ctx, tmObject=None)}
<object type="image/svg+xml" style="width:100%; height:auto;" data="img/${tmo._id}_ATTACKTREE.svg"></object>
<img src="img/legend_AttackTree.svg" width="600"/>

${PAGEBREAK}
<hr/>
${makeMarkdownLinkedHeader(headerLevel+1, tmo.title +' Threats', ctx, tmObject=None)}

> **Note** This section contains the threat and mitigations identified during the analysis phase.


% for i , threat in enumerate(tmo.threats):
%if i > 1:
<hr/> \
%endif
${lib.renderThreat(threat, headerLevel)}
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

</div>

</%def>
