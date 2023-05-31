from __future__ import annotations
from dataclasses import dataclass, field
from typing import List, Tuple, Optional, Union
import datetime



EMPTYLIST = field(default_factory=list)
'''
Threats
'''

@dataclass 
class ThreatCVSS:
  vector:   str   = ""
  severity: str   = "None"
  score:    float = 0.0


@dataclass 
class CounterMeasureReference:
  REFID: str

  countermeasure: CounterMeasure = field(init=False, default=None, repr=False)

  #def __post_init__(self):
  #  self.countermeasure = lookup_countermeasureA()



@dataclass 
class CounterMeasure:
  ID: str
  description: str = ""
  inPlace: bool = False
  public: bool = False
  operational: bool = False
  #vulnManagementLink: str = field(init=False, default=None)



@dataclass 
class ImpactReference:
  REFID: str

@dataclass 
class AssetReference:
  ID: str


@dataclass 
class Threat:
  ID: str
  title: str  
  attack: str
  threatType: str

  assets: list[AssetReference] 
  CVSS: ThreatCVSS
  
  
  public: bool
  fullyMitigated: bool
  
  impact: str = None
  impacts: list[ImpactReference] = EMPTYLIST#field(default_factory=list)  
  countermeasures: list[Union[CounterMeasure, CounterMeasureReference]] = EMPTYLIST

  

  def __post_init__(self):
    for cm in self.countermeasures:
      cm.parent = self;

'''
Scope
'''

@dataclass 
class Asset:
  ID: str
  title: str = field(init=False,default=None)
  type: str
  description: str 
  inScope: bool


@dataclass 
class Scope:
  description: str
  diagram: str = None
  assets: List[Asset] = field(default_factory=list)

  #comments: CommentedDict

'''
Threat Model
'''
@dataclass 
class GanttChart:
  startDate: datetime.date
  endDate: datetime.date
  state: str = None

@dataclass 
class ThreatModel:

  #class _(YAMLWizard.Meta):
  #  debug_enabled = True

  parent: str
  ID: str
  #jiraLink: str

  scope: Scope
  threats: List[Threat]

  assets: List[Asset] = EMPTYLIST

  analysis: str = None
  gantt: GanttChart = None

  #children: list[ThreatModel]