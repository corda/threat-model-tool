<%! import html %>
<%! from r3threatmodeling.template_utils import createTitleAnchorHash, makeMarkdownLinkedHeader, mermaid_escape, valueOr  %>

<%namespace name="lib" file="lib.mako"/> 
# GANTT

<!-- mermaid start. Do not delete this comment-->
```mermaid
gantt
    title C5 Threat Models
    dateFormat  YYYY-MM-DD
    excludes weekends
    section ${tmo.title}
% for descendantTM in tmo.getDescendants():
%if hasattr(descendantTM, "gantt"): 
${descendantTM.title}     : ${descendantTM.gantt['status']}, ${descendantTM.gantt['startDate']}, ${descendantTM.gantt['endDate']}
## %else:
## ${descendantTM.title}     : 2023-05-1, 40d
% endif 
% endfor
```
<!-- mermaid end. comment needed to it covert to HTML-->


## ${makeMarkdownLinkedHeader(2, 'Requests For Information')}


