from pyConThreatMod import *
from pyvis.network import Network

def createEmptyNet():
  net = Network(notebook=False, directed =True,  layout=True)
  net.set_options("""
  const options = {
    "nodes": {
      "shape": "square",
      "borderWidth": 2,
      "borderWidthSelected": 4,
      "opacity": null,
      "size": 50,
      "widthConstraint" :
        { "maximum": 170 }
    },
    "edges": {
      "color": {
        "inherit": true
      },
      "selfReferenceSize": null,
      "selfReference": {
        "angle": 0.7853981633974483
      },
      "smooth": false
    },
    "layout": {
      "hierarchical": {
        "enabled": true,
        "levelSeparation": 205,
        "nodeSpacing": 200,
        "treeSpacing": 285
      }
    },
    "physics": {
      "enabled": false,
      "hierarchicalRepulsion": {
        "centralGravity": 0,
        "avoidOverlap": null
      },
      "minVelocity": 0.75,
      "solver": "hierarchicalRepulsion"
    }
  }
  """)
  return net
              
# """
#  {
#   hierarchical: {
#     direction: 'UD',
#     nodeSpacing: 150,
#     sortMethod : 'directed' //hubsize, directed.
#   }
# }
# """

# net.add_node(1, label="Node 1")
# net.add_nodes([1,2,3], value=[10, 100, 400],
#                          title=['I am node 1', 'node 2 here', 'and im node 3'],
#                          x=[21.4, 54.2, 11.2],
#                          y=[100.2, 23.54, 32.1],
#                          label=['NODE 1', 'NODE 2', 'NODE 3'],
#                          color=['#00ff1e', '#162347', '#dd4b39'])

# net.add_edge(2, 1, weight=.87)
# net.add_node("root", label="ROOT", level=0)


tmDict = parseYamlThreatModelAndChildren(open("threatModels/C5.yaml"))
c5ThreatModel = ThreatModel(tmDict)

securityObjectives = c5ThreatModel.securityObjectives

group = None
level = 0
for i, so in enumerate(securityObjectives):
    net = createEmptyNet()
    if so.group != group:
       group = so.group
       level = level+1
    if i ==0:
       level = 0;
    print(f"{so.id} {so.title}")
    net.add_node(so.id, so.title, level=level, shape='box', color='pink')
    if i ==0:
       level = 1;
    
    # for so_contrib in so.contributesTo:
    #    net.add_edge(so.id, so_contrib.id, color='red', label = "impacts")

    level = level +1 
    for threat in c5ThreatModel.getAllDown('threats'):
        if threat.impacts:
          print(f"{threat.id} {threat.title}")
          for so_im in threat.impacts:
              if so_im.id == so.id: 
                # print(f"   impact: {so_im.id} {so_im.title}")
                net.add_node(threat.id, label=f"{threat.id}\n{threat.title}",  level=level, shape='box', color='lightGrey') 
                net.add_edge(threat.id, so_im.id, color='red', label ="exploits")
                for countermeasure in threat.countermeasures:
                    if countermeasure.inPlace:
                      threatColor = 'lightGreen'
                    else:
                      threatColor = 'yellow'
                       
                    net.add_node(countermeasure.id, label=countermeasure.title, level=level+1, shape='box', color=threatColor) 
                    net.add_edge(countermeasure.id, threat.id, color='green', label="mitigates")
        # else:
        #     net.add_node(threat.id, label=f"{threat.title}\n{threat.id} ", level=level+3, shape='box', color='pink') 
        #     for countermeasure in threat.countermeasures:
        #         net.add_node(countermeasure.id, label=countermeasure.title, level=level+4, shape='box', color='lightGreen') 
        #         net.add_edge(countermeasure.id, threat.id, color='green', label="mitigates")
    net.show(f'threatModels/generated_reports/attackTrees/{so.id}.html', notebook=False)

# net.toggle_physics(False)
# net.show_buttons()




# for threatModel in c5ThreatModel.childrenTM:
#     print(f" Threat model title: {threatModel.title}")
#     for threat in threatModel.getThreatsByFullyMitigatedAndOperational(False, False):
#         print(f"""     Threat (ID) title: ({threat.ID}) {threat.title}
#                         link: https://github.com/corda/threat-modeling/blob/master/threatModels/generated_reports/C5.md#{createTitleAnchorHash(f"({threat._id}) " +threat.title)}
#         """)
        






