from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict, Any, Set, Union
import networkx as nx
import jsonschema
from ruamel.yaml import YAML
import copy
import re
import os
import semantic_version
from collections import defaultdict

yaml = YAML(typ='safe')

# --- Extended CVSS class with smart scoring capabilities ---
class TMCVSS(CVSS3):
    def getSmartScoreIndex(self):
        scores = self.scores()
        base, temporal, environmental = scores
        
        index = None  
        if base == temporal and base == environmental:
            index = 0
        elif base == temporal and base != environmental:
            index = 2
        elif base != temporal and temporal == environmental:
            index = 1
        else:
            index = scores.index(max(temporal, environmental))
        return index
        
    scoresNames = ("Base score", "Temporal score", "Environmental score")
    
    def getSmartScoreType(self):
        scoresNames = self.scoresNames
        index = self.getSmartScoreIndex()
        ret = f"{scoresNames[index]}"
        return ret

    def getSmartScoreDesc(self):
        index = self.getSmartScoreIndex()
        ret = f"{self.scores()[index]} ({self.severities()[index]})"
        return ret

    def getSmartScoreColor(self):
        score = self.getSmartScoreVal()
        if score == 0.0:
            return "#53aa33"
        elif score <= 3.9:
            return "#ffcb0d"
        elif score <= 6.9:
            return "#f9a009"
        elif score <= 8.9:
            return "#df3d03"
        elif score <= 10:
            return "#cc0500"
        else:
            return "gray"

    def getSmartScoreVal(self):
        index = self.getSmartScoreIndex()
        ret = self.scores()[index]
        return ret
    
    def getSmartScoreSeverity(self):
        index = self.getSmartScoreIndex()
        ret = self.severities()[index]
        return ret

# --- Data Model Definitions ---

@dataclass
class Countermeasure:
    ID: str
    title: str
    description: str
    inPlace: bool
    public: bool
    operational: bool = False
    operator: Optional[str] = None
    _id: str = field(init=False)
    isReference: bool = False

    def __post_init__(self):
        self._id = self.ID

    def RAGStyle(self):
        if not hasattr(self, "inPlace"):
            return "countermeasureNIP"
        if self.inPlace:
            return "countermeasureIP"
        return "countermeasureNIP"

    def statusColors(self):
        inPlace = {'border': '#82B366', 'fill': '#D5E8D4'}
        notInPlace = {'border': '#D6B656', 'fill': '#FFF2CC'}

        if not hasattr(self, "inPlace"):
            return notInPlace
        if self.inPlace:
            return inPlace
        return notInPlace

class _BaseTMObj:
    parent: Optional[Any] = None
    children: Set[Any] = field(default_factory=set)
    _id: str = None

    @property
    def id(self):
        return getattr(self, "_id", getattr(self, "ID", None))

    @property
    def anchor(self):
        id = self.id
        if id is None:
            return ""
        return id[id.find('.')+1:] if '.' in id else id

    @property
    def uri(self):
        if not self.parent:
            return self.id
        root = self.getRoot()
        return root._id + '/#' + self.anchor

    def getRoot(self):
        if getattr(self, "parent", None) is None:
            return self
        return self.parent.getRoot()

    def getDescendantById(self, id):
        if not hasattr(self, 'children'):
            return None
        for x in self.children:
            if getattr(x, "_id", None) == id:
                return x
        for x in self.children:
            res = x.getDescendantById(id)
            if res is not None:
                return res
        return None

    def getDescendantFirstById(self, id):
        res = self.getDescendantById(id)
        if res is not None:
            return res
        if not hasattr(self, 'childrenTM'):
            return self.getDescendantById(id)
        for tm in self.childrenTM:
            res = tm.getDescendantFirstById(id)
            if res is not None:
                return res
        return None

    def getAllUp(self, attrName):
        if self.parent is None:
            return getattr(self, attrName, [])
        else:
            return self.parent.getAllUp(attrName) + getattr(self, attrName, [])
    
    def getFirstUp(self, attrName):
        if self.parent is None:
            if hasattr(self, attrName):
                return getattr(self, attrName)
            else:
                return None
        else:
            return self.parent.getFirstUp(attrName)

@dataclass
class SecurityObjective(_BaseTMObj):
    ID: str
    title: str
    description: str
    group: str
    contributesTo: List[Any] = field(default_factory=list)
    _id: str = field(init=False)
    parent: Optional[Any] = None
    treeImage: bool = True
    priority: str = "High"
    inScope: bool = True

    def __post_init__(self):
        self._id = self.ID

    def linkedImpactMDText(self):
        return f"<code><a href=\"#{self.anchor}\">{self._id}</a></code>"

    def contributedToMDText(self):
        return f"<code><a href=\"#{self.anchor}\">{self._id}</a></code> *({self.title})*"

    def shortText(self):
        firstPara = self.description.split("\n")[0]
        return f"*{self.id}*\n({firstPara})"

    @property
    def treeImage(self):
        # If there are not direct threats do not show the empty tree
        root = self.getRoot()
        for threat in root.getAllDown('threats'):
            for impactedSecObj in getattr(threat, 'impactedSecObj', []):
                if impactedSecObj.id == self.id: 
                     return self.treeImage
        return False

@dataclass
class Asset(_BaseTMObj):
    ID: str
    type: str
    title: str
    description: str
    inScope: bool
    _id: str = field(init=False)
    parent: Optional[Any] = None

    def __post_init__(self):
        self._id = self.ID

    def propertiesHTML(self):
        if not hasattr(self, 'properties'):
            return ""
        ret = "<ul>"
        try:
            for k, v in self.properties.items():
                ret = ret + f"<li style='margin: 0px 0;'><b>{k}:</b> &nbsp;{v}</li>"
        except:
            pass
        return ret + "</ul>"

    @property
    def inScope(self):
        try:
            return 'Yes' if self.inScope else 'No'
        except:
            raise BaseException("asset "+ self.id +" missing valid boolean inScope attribute ")

@dataclass
class Attacker(_BaseTMObj):
    ID: str
    description: str
    inScope: bool
    title: Optional[str] = None
    _id: str = field(init=False)
    parent: Optional[Any] = None

    def __post_init__(self):
        self._id = self.ID
        if not self.title:
            self.title = self.ID

@dataclass
class Threat(_BaseTMObj):
    ID: str
    title: str
    attack: str
    threatType: str
    impactDesc: str
    impactedSecObj: List[Any]
    attackers: List[Any]
    CVSS: Dict[str, Any]
    fullyMitigated: bool
    countermeasures: List[Countermeasure] = field(default_factory=list)
    assets: List[Any] = field(default_factory=list)
    parent: Optional[Any] = None
    _id: str = field(init=False)
    threatModel: Optional[Any] = None
    cvssObject: Optional[Any] = None

    def __post_init__(self):
        self._id = self.ID
        # CVSS object for scoring
        if self.CVSS and "vector" in self.CVSS and self.CVSS["vector"]:
            try:
                from cvss import CVSS3
                self.cvssObject = CVSS3(self.CVSS["vector"])
            except Exception:
                self.cvssObject = None
        else:
            self.cvssObject = None

    @property
    def description(self):
        return "**Attack:** " + self.attack + "<br/> **Impact:** " + self.impactDesc

    @property
    def attack_desc(self):
        return self.attack

    @property
    def impact_desc(self):
        ret = ""
        if hasattr(self, 'impactDesc'):
            ret += self.impactDesc + "<br/> "
        if hasattr(self, 'impactedSecObj'):
            for secObj in self.impactedSecObj:
                try:
                    ret += secObj.linkedImpactMDText() + "<br/> "
                except Exception:
                    pass
        return ret

    def threatGeneratedTitle(self):
        assetDesc = " in: "
        if hasattr(self, 'assets') and self.assets:
            for asset in self.assets:
                assetDesc += f"{asset.type} {asset.title}, "
            return self.threatType + assetDesc[:-2]
        else:
            return self.threatType

    @property
    def operational(self):
        for cm in self.countermeasures:
            if getattr(cm, "operational", False):
                return True
        return False

    def hasOperationalCountermeasures(self):
        for cm in self.countermeasures:
            if getattr(cm, "operational", False):
                return True
        return False

    @property
    def ticketLink(self):
        return getattr(self, "_ticketLink", None)
    
    @ticketLink.setter
    def ticketLink(self, value):
        self._ticketLink = value
        if hasattr(self.originDict, 'insert') and 'ticketLink' not in self.originDict:
            # It may be not an ordered dict (with insert method) as in ruamel yaml parser
            self.originDict.insert(1, 'ticketLink', value)
        else:
            self.originDict.update({'ticketLink': value})
    
    def getOperationalCountermeasures(self):
        return [cm for cm in self.countermeasures if getattr(cm, "operational", False)]

@dataclass
class ThreatModel(_BaseTMObj):
    ID: str
    title: str
    version: str
    authors: str
    scope: Dict[str, Any]
    analysis: Optional[str]
    threats: List[Threat] = field(default_factory=list)
    securityObjectives: List[SecurityObjective] = field(default_factory=list)
    assets: List[Asset] = field(default_factory=list)
    attackers: List[Attacker] = field(default_factory=list)
    childrenTM: List[Any] = field(default_factory=list)
    _id: str = field(init=False)
    parent: Optional[Any] = None
    fileName: Optional[str] = None
    assumptions: List[Any] = field(default_factory=list)

    def __post_init__(self):
        self._id = self.ID
        self.children = set()
        for so in self.securityObjectives:
            so.parent = self
        for asset in self.assets:
            asset.parent = self
        for attacker in self.attackers:
            attacker.parent = self
        for threat in self.threats:
            threat.parent = self
            threat.threatModel = self

    def getAllDown(self, attrName):
        ret = getattr(self, attrName, [])
        for c in getattr(self, "childrenTM", []):
            ret = ret + c.getAllDown(attrName)
        return ret

    def getAllAttackers(self):
        if self.parent is None:
            return self.attackers
        else:
            return self.parent.getAllAttackers() + self.attackers

    def getAssetById(self, id):
        for x in self.getAllDown('assets'):
            if getattr(x, "_id", None) == id:
                return x
        raise Exception("Asset with ID not found in "+ self._id+ ": " + id)

    def getById(self, id):
        return self.getRoot().getDescendantFirstById(id)

    def getThreatsByFullyMitigated(self, fullyMitigated):
        ts = [t for t in self.getAllDown('threats') if t.fullyMitigated is fullyMitigated]
        return sorted(ts, key=lambda x: x.getSmartScoreVal(), reverse=True)

    def getThreatsByFullyMitigatedAndOperational(self, fullyMitigated, operational):
        ts = [t for t in self.getAllDown('threats') if (t.fullyMitigated is fullyMitigated and t.operational is operational)]
        return sorted(ts, key=lambda x: x.getSmartScoreVal(), reverse=True)

    def getDescendantsTM(self):
        descendants = []
        for child in getattr(self, "childrenTM", []):
            descendants.append(child)
            descendants.extend(child.getDescendantsTM())
        return descendants

    def isRoot(self):
        return self.parent is None

    def checkThreatModelConsistency(self):
        """
        Check the consistency of the threat model.
        This includes checking the following:
        - If a threat is fully mitigated, at least one mitigation should be 'inPlace' true.
        - If a threat is not fully mitigated, there should be no mitigation 'inPlace' true.
        - If a threat is public = true, the threat should be fully mitigated.
        - If a threat is fully mitigated and public, at least one countermeasure should be 'inPlace' true and public = true.
        """
        warnings = []

        for threat in self.getAllDown('threats'):
            if threat.fullyMitigated:
                has_inplace = any(cm.inPlace for cm in threat.countermeasures)
                if not has_inplace:
                    warnings.append(f"Threat '{threat.id}' is fully mitigated but has no 'inPlace' countermeasures.")
            else:
                has_inplace = any(cm.inPlace for cm in threat.countermeasures)
                if has_inplace:
                    warnings.append(f"Threat '{threat.id}' is not fully mitigated but has 'inPlace' countermeasures.")

            if hasattr(threat, 'public') and threat.public and not threat.fullyMitigated:
                warnings.append(f"Threat '{threat.id}' is public but not fully mitigated.")

            if threat.fullyMitigated and hasattr(threat, 'public') and threat.public:
                has_inplace_and_public = any(cm.inPlace and hasattr(cm, 'public') and cm.public for cm in threat.countermeasures)
                if not has_inplace_and_public:
                    warnings.append(f"Threat '{threat.id}' is fully mitigated and public but has no 'inPlace' and public countermeasures.")

        if warnings:
            print("Threat Model Consistency Warnings:")
            for warning in warnings:
                print(f"WARNING!!! - {warning}")

    def getOperationalGuideData(self):
        """
        Extract operational guide data for countermeasures.
        """
        guideData = {}

        ts = [t for t in self.getAllDown('threats') if (t.operational is True)]
        ts = sorted(ts, key=lambda x: x.getSmartScoreVal(), reverse=True)

        cms = []
        operators = set()
        for t in ts:
            for c in t.countermeasures:
                if not c.isReference and c.operational:
                    cms.append(c)
                    operators.add(c.operator)

        for op in operators:
            guideData[op] = []

        for countermeasure in cms:
            guideData[countermeasure.operator].append(countermeasure)

        return guideData

    def dumpRecursive(self, folder=None, prefix="", encoding="utf-8", recursive=True):
        """
        Dump the threat model and its children recursively into YAML files.
        """
        originalFolder, fn = os.path.split(self.fileName)

        if folder is None:
            folder = originalFolder
        fn = prefix + fn
        path = folder + os.path.sep + fn
        outputStream = open(path, "wt", encoding=encoding)

        print(f"...dumping yaml file: {path}")
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.dump(self.originDict, outputStream)

        if recursive:
            for childrenTM in self.childrenTM:
                childrenTM.dumpRecursive(prefix=prefix, encoding=encoding, recursive=recursive)

    # Add this method to get the asset directory
    def assetDir(self):
        return os.path.dirname(self.fileName) + "/assets"
    
    def getAssetsByProps(self, **kwargs):
        """Return assets that match all provided properties"""
        return [asset for asset in self.getAllDown('assets') 
                if all(getattr(asset, key, None) == value for key, value in kwargs.items())]
    
    def getChildrenTMbyID(self, id):
        """Get a child ThreatModel by ID"""
        return next((tmo for tmo in self.childrenTM if tmo._id == id), None)
    
    def get_ISO27001_groups_titles(self):
        """
        Returns a list of unique group descriptions found in the ISO27001 reference items.
        """
        if not hasattr(self, 'ISO27001Ref'):
            return []
            
        group_descriptions = set()
        for item in self.ISO27001Ref:
            if isinstance(item, dict) and 'group' in item:
                group_descriptions.add(item['group'])
        
        return list(group_descriptions)

    def get_ISO27001_grouped_ids(self):
        """
        Returns a dictionary mapping group descriptions to a list of their
        associated ISO27001 reference IDs.
        """
        if not hasattr(self, 'ISO27001Ref'):
            return {}
            
        group_ids_dict = defaultdict(list)
        
        for item in self.ISO27001Ref:
            if isinstance(item, dict) and 'group' in item and 'ID' in item:
                group = item['group']
                item_id = item['ID']
                group_ids_dict[group].append(item_id)
        
        return dict(group_ids_dict)

# --- JSON Schema Example (minimal) ---
THREATMODEL_SCHEMA = {
    "type": "object",
    "properties": {
        "ID": {"type": "string"},
        "title": {"type": "string"},
        "version": {"type": "string"},
        "authors": {"type": "string"},
        "children": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ID": {"type": "string"}
                },
                "required": ["ID"]
            }
        },
        "scope": {
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "securityObjectives": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ID": {"type": "string"},
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "group": {"type": "string"},
                            "contributesTo": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "REFID": {"type": "string"}
                                    },
                                    "required": ["REFID"]
                                }
                            }
                        },
                        "required": ["ID", "title", "description", "group"]
                    }
                },
                "assets": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ID": {"type": "string"},
                            "type": {"type": "string"},
                            "title": {"type": "string"},
                            "description": {"type": "string"},
                            "inScope": {"type": "boolean"},
                            "properties": {
                                "type": "object",
                                "additionalProperties": true
                            }
                        },
                        "required": ["ID", "type", "title", "description", "inScope"]
                    }
                },
                "attackers": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ID": {"type": "string"},
                            "description": {"type": "string"},
                            "inScope": {"type": "boolean"},
                            "title": {"type": "string"}
                        },
                        "required": ["ID", "description", "inScope"]
                    }
                },
                "assumptions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "ID": {"type": "string"},
                            "description": {"type": "string"}
                        },
                        "required": ["ID", "description"]
                    }
                }
            },
            "required": ["description"]
        },
        "analysis": {"type": ["string", "null"]},
        "threats": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ID": {"type": "string"},
                    "title": {"type": "string"},
                    "ticketLink": {"type": "string"},
                    "attack": {"type": "string"},
                    "threatType": {"type": "string"},
                    "impactDesc": {"type": "string"},
                    "conditional": {"type": "string"},
                    "appliesToVersions": {"type": "string"},
                    "impactedSecObj": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "REFID": {"type": "string"}
                            },
                            "required": ["REFID"]
                        }
                    },
                    "assets": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "REFID": {"type": "string"}
                            },
                            "required": ["REFID"]
                        }
                    },
                    "attackers": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "REFID": {"type": "string"}
                            },
                            "required": ["REFID"]
                        }
                    },
                    "CVSS": {
                        "type": "object",
                        "properties": {
                            "vector": {"type": "string"},
                            "base": {"type": ["string", "null"]}
                        }
                    },
                    "fullyMitigated": {"type": "boolean"},
                    "countermeasures": {
                        "type": "array",
                        "items": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "properties": {
                                        "ID": {"type": "string"},
                                        "title": {"type": "string"},
                                        "description": {"type": "string"},
                                        "inPlace": {"type": "boolean"},
                                        "public": {"type": "boolean"},
                                        "operational": {"type": "boolean"},
                                        "operator": {"type": "string"},
                                        "mitigationType": {"type": "string"},
                                        "appliesToVersions": {"type": "string"}
                                    },
                                    "required": ["ID", "description", "inPlace", "public"]
                                },
                                {
                                    "type": "object",
                                    "properties": {
                                        "REFID": {"type": "string"},
                                        "notes": {"type": "string"}
                                    },
                                    "required": ["REFID"]
                                }
                            ]
                        }
                    }
                },
                "required": ["ID", "attack", "threatType", "impactDesc", "CVSS", "fullyMitigated"]
            }
        }
    },
    "required": ["ID", "title", "version", "scope"],
    "additionalProperties": true
}

def validate_yaml_schema(data: dict, schema: dict = THREATMODEL_SCHEMA):
    jsonschema.validate(instance=data, schema=schema)

def parse_countermeasure(cm_dict: dict) -> Countermeasure:
    return Countermeasure(**cm_dict)

def _lookup_by_id(objects, refid):
    for obj in objects:
        if getattr(obj, "ID", None) == refid:
            return obj
    return None

def _expand_refids(ref_list, candidates):
    result = []
    for entry in ref_list:
        if isinstance(entry, dict) and "REFID" in entry:
            refid = entry["REFID"]
            ref_obj = _lookup_by_id(candidates, refid)
            if ref_obj is not None:
                ref_copy = copy.copy(ref_obj)
                ref_copy.isReference = True
                result.append(ref_copy)
        else:
            result.append(entry)
    return result

def parse_threat(threat_dict: dict, secobjs=None, attackers=None) -> Threat:
    cms = [parse_countermeasure(cm) for cm in threat_dict.get('countermeasures', [])]
    impactedSecObj = threat_dict.get('impactedSecObj', [])
    attackers_list = threat_dict.get('attackers', [])
    
    if secobjs is not None:
        impactedSecObj = _expand_refids(impactedSecObj, secobjs)
    if attackers is not None:
        attackers_list = _expand_refids(attackers_list, attackers)
    
    threat = Threat(
        countermeasures=cms,
        impactedSecObj=impactedSecObj,
        attackers=attackers_list,
        **{k: v for k, v in threat_dict.items() if k not in ['countermeasures', 'impactedSecObj', 'attackers']}
    )
    
    # Set CVSS object using TMCVSS if available
    if threat.CVSS and "vector" in threat.CVSS and threat.CVSS["vector"]:
        try:
            threat.cvssObject = TMCVSS(threat.CVSS["vector"])
        except Exception:
            threat.cvssObject = None
    
    return threat

def parse_security_objective(obj: dict) -> SecurityObjective:
    return SecurityObjective(**obj)

def parse_asset(obj: dict) -> Asset:
    return Asset(**obj)

def parse_attacker(obj: dict) -> Attacker:
    return Attacker(**obj)

def parse_threatmodel(yaml_path: str, parent=None) -> ThreatModel:
    with open(yaml_path, encoding="utf-8") as f:
        data = yaml.load(f)
    validate_yaml_schema(data)
    secobjs = [parse_security_objective(o) for o in data.get('scope', {}).get('securityObjectives', [])]
    assets = [parse_asset(a) for a in data.get('scope', {}).get('assets', [])]
    attackers = [parse_attacker(a) for a in data.get('scope', {}).get('attackers', [])]
    threats = [parse_threat(t, secobjs=secobjs, attackers=attackers) for t in data.get('threats', [])]
    tm = ThreatModel(
        threats=threats,
        securityObjectives=secobjs,
        assets=assets,
        attackers=attackers,
        **{k: v for k, v in data.items() if k not in ['threats', 'scope']}
    )
    tm.parent = parent
    if "children" in data:
        for child in data["children"]:
            child_path = re.sub(r"/[^/]+\.yaml$", "", yaml_path) + "/" + child["ID"] + "/" + child["ID"] + ".yaml"
            child_tm = parse_threatmodel(child_path, parent=tm)
            tm.childrenTM.append(child_tm)
    return tm

def build_threatmodel_graph(tm: ThreatModel) -> nx.DiGraph:
    G = nx.DiGraph()
    G.add_node(tm.ID, obj=tm)
    for so in tm.securityObjectives:
        G.add_node(so.ID, obj=so)
        G.add_edge(tm.ID, so.ID)
    for asset in tm.assets:
        G.add_node(asset.ID, obj=asset)
        G.add_edge(tm.ID, asset.ID)
    for attacker in tm.attackers:
        G.add_node(attacker.ID, obj=attacker)
        G.add_edge(tm.ID, attacker.ID)
    for threat in tm.threats:
        G.add_node(threat.ID, obj=threat)
        G.add_edge(tm.ID, threat.ID)
        for cm in threat.countermeasures:
            G.add_node(cm.ID, obj=cm)
            G.add_edge(threat.ID, cm.ID)
    return G

# --- Function to validate the structure of threat objects ---
def matchesAllProps(obj, **kwargs):
    """Check if an object matches all provided properties"""
    for key, value in kwargs.items():
        try:
            if getattr(obj, key) != value:
                return False
        except:
            return False
    return True

