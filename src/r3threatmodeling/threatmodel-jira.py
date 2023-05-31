from threatmodel import ThreatModel
from dacite import from_dict
from dataclasses import asdict
from pprint import pprint
#import pathlib

#from ruamel.yaml import YAML
#yaml = YAML(typ='rt')
import yaml

#tmd = load(tmstr, yaml.SafeLoader)
#ytm = yaml.load(open("threatModels/VNodeOnboarding.yaml").read())
#ytm = yaml.load(open("threatModels/VNodeOnboarding.yaml").read(), yaml.SafeLoader)

ytm = yaml.load(open("threatModels/Sandboxes.yaml").read(), yaml.SafeLoader)

#print(ytm)
tm = from_dict(data_class=ThreatModel, data=ytm)
#tm = ThreatModel.from_yaml(open().read())

#tm.threats[0].countermeasures[0].jira_link()

#pprint(tm, compact=True)

d=asdict(tm)
yaml.emitter.Emitter.process_tag = lambda self, *args, **kw: None
y=yaml.dump(d, sort_keys=False)#tm)
print(y)

for threat in tm.threats:
  print(threat.ID, threat.title)