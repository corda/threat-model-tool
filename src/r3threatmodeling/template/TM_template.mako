<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<% PAGEBREAK = """<br style="page-break-before: always"><div class="pagebreak"></div>"""%>
<% H6 = """###### """ %>
<%namespace name="lib" file="lib.mako"/> 

##TITLE
% if hasattr(tmo, 'title'):
${makeMarkdownLinkedHeader(1, tmo.title + ' Threat Model', skipTOC = False)}
%else:
${makeMarkdownLinkedHeader(1, tmo._id.replace('_', ' ') + ' Threat Model', skipTOC = False)}
%endif


% if tmo.parent != None:
**Parent Threat Model**: [${tmo.parent.id.replace('_', ' ')}](${tmo.parent.id}.md) <br/>
% endif

**Full ID used as prefix:** ${tmo.id}

## as this double dash is also the comment for MAKO template...
${makeMarkdownLinkedHeader(2, 'Table of Contents', skipTOC = True)}

__TOC_PLACEHOLDER__


## % for threat in tmo.threats:
##     + [${threat.id ${threat.threatType} ](#${threat.id}-${threat.threatType.replace(" ","-").replace(",","-")})
## % if 'countermeasures' in threat:
##         + [Countermeasures](#${threat.id}-Countermeasures)
## % endif
## % endfor


${PAGEBREAK}
% if tmo.parent != None:
${makeMarkdownLinkedHeader(1, 'Parent Scope: ' + tmo.parent.id.replace('_', ' '))}

${tmo.parent.scope.description}
${PAGEBREAK}
${makeMarkdownLinkedHeader(2, 'Parent Scope diagrams')} 

${tmo.parent.scope.diagram}

% endif

${PAGEBREAK}

${makeMarkdownLinkedHeader(1, tmo._id.replace('_', ' ') +  ' scope of analysis')}

${tmo.scope.description}
%if hasattr(tmo.scope, "diagram"):
${makeMarkdownLinkedHeader(2, 'Diagrams')}
${tmo.scope.diagram}
%endif 

${PAGEBREAK}
${makeMarkdownLinkedHeader(2, 'Attackers')}

This section contains the list of attacker, personas, roles and potential threat agents.
###  Defined in this threat model 

% if len(tmo.attackers) == 0:
No attackers defined in this scope
% else:

% for attacker in tmo.attackers:
${lib.renderAttacker(attacker)}
% endfor

% endif

% if tmo.parent != None:


% if len(tmo.parent.getAllAttackers()) == 0:
No other attackers inherited
% else:

${makeMarkdownLinkedHeader(3, 'Attackers inherited from parents threat model')}

% for attacker in tmo.parent.getAllAttackers():
${lib.renderAttacker(attacker)}

% endfor

% endif

% endif
${PAGEBREAK}
${makeMarkdownLinkedHeader(2, 'Assets')}

${makeMarkdownLinkedHeader(3, 'Summary Table')}

${lib.renderAssetTable(tmo.assets)}

${makeMarkdownLinkedHeader(3, 'Details')}

% for asset in tmo.assets:
${lib.renderAsset(asset)} 
% endfor


## % if not tmo.isRoot():
## ${H2} Parent Scope Assets
## % for asset in tmo.parent.getAll('assets'): 
## ${lib.renderAsset(asset)} 
## % endfor
## % endif
${makeMarkdownLinkedHeader(2, 'Assumptions')}

% for assumption in tmo.assumptions:
 **${assumption._id}:**
  ${assumption.description} 

% endfor

% if hasattr (tmo, 'analysis'):
${PAGEBREAK}
${makeMarkdownLinkedHeader(1, 'Analysis')}

This section to documents the work performed to identify threats and thier mitigations.
It may contains notes from the analysis sessions.
This analysis part may be omitted in future reports.

${tmo.analysis}  
% endif
${PAGEBREAK}
${makeMarkdownLinkedHeader(1, 'Threats')}

This section contains the threat and mitigations identified during the analysis phase.


% for threat in tmo.threats:
${lib.renderThreat(threat)}
${PAGEBREAK}
 % endfor

