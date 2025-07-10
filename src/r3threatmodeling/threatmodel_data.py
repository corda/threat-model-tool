"""
R3 Threat Modeling 
"""

"""
    
"""
from xml.etree.ElementPath import get_parent_map
from ruamel.yaml import YAML
from ruamel.yaml.error import YAMLError
from collections import defaultdict
#import yaml
yaml=YAML(typ='rt')

import os
import re
from io import StringIO
import html
import copy
import semantic_version
from cvss import CVSS3

ANY_VERSION_MATCHER = semantic_version.Spec(">0.0.0")

def matchesAllPros(object, **kwargs):
    for key, value in kwargs.items():
        try:
            if getattr(object, key) != value:
                return False
        except:
            return False
    return True


class BaseThreatModelObject:

    originDict= None

    def matchesVersion(self, appliesToVersion):
        if not self.versionsFilter:
            return True
        return not not list(semantic_version.SimpleSpec(appliesToVersion).filter(self.versionsFilter))

    def filterOutForPublicOrVersions(self, public, dict):
        return self.filterOutForPublic(public, dict) or self.filterOutForVersions(dict)

    def filterOutForVersions(self, dict):
        return 'appliesToVersions' in dict and not self.matchesVersion(dict['appliesToVersions'])

    def filterOutForPublic(self, public, dict):
        return public and 'public' in dict and dict['public'] == False
    
    def update(self, dict):
        try: 
            self.originDict.update(dict)
        except:
            raise BaseException(f"originDict not set by the object parser in: {self.id}")

    @property
    def id(self):
        if not hasattr(self, '_id'):
            return None
        
        if self.parent is not None:
            try:
                lid = self.parent.id + "." + self._id
            except:
                #No idea why I need this... for countermeasure parsing etc...
                return self.parent._id + "." + self._id
            return lid
        else:
            #if isinstance(self, SecurityObjective):
            #    prefix='SO'
            #elif isinstance(self, SecurityObjective):
            #    prefix=''
            return self._id
    @id.setter
    def id(self, id):
        if not re.match("^[a-zA-Z0-9_]*$", id):
        # if " " in id:
            raise BaseException(f"ID does support other chars than alphanumeric and _ , pls change this ID: {id} (parent: {self.parent.id} )")
        self._id = id


    @property
    def anchor(self):
        id = self.id
        return id[id.find('.')+1:] #exclude the first TMID. from the anchor


    @property
    def uri(self):
        if not self.parent:
            return self.id
        
        root = self.getRoot()
        return root._id + '/#' + self.anchor
        
    isReference = False 
    

    @property
    def versionsFilter(self):
        if not hasattr(self, '_versionsFilter'):
            return self.getRoot().versionsFilter ##TODO check this function
        else:
            return self._versionsFilter


    @property
    def title(self):
        if not hasattr(self, '_title'):
            return self.description[0:50] + "[...]"
        else:
            return self._title
    @title.setter
    def title(self, title):
        self._title = title

    def __init__(self):

        return
    def __init__(self, dict, parent):

        # if "ID" in dict and dict["ID"] is not None and "." in dict["ID"]:
        #     dict["ID"] = dict["ID"].replace(".","_").upper()

        self.originDict = dict

        self.description = ""
        self.parent = parent

        if hasattr(parent, "children"):
            parent.children.add(self)
        else:
            parent.children = {self}

        if "ID" in dict:
            self._id = dict["ID"]
        else:
            self._id = "undefined"
        for k, v in dict.items():
            setattr(self, k, v)


    def printAsText(self):
        return "\nID: " + self.id + " \nDescription: " + self.description
    
    #Get all elements recursive form parents
    def getAllUp(self, attrName):
        if self.parent is None:
            return getattr(self, attrName)
        else:
            return self.parent.getAllUp(attrName) + getattr(self, attrName)

    def getFirstUp(self, attrName):
        if self.parent is None:
            if hasattr(self, attrName):
                return getattr(self, attrName)
            else:
                return None
        else:
            return self.parent.getFirstUp(attrName)
        
    def getAllDown(self, attrName):
        ret = getattr(self, attrName, [])
        for c in self.childrenTM:
            ret = ret + c.getAllDown(attrName)
        return ret

    def getAllDownByType(self, typeName):
        
        """
        Get all objects of a specific type in the threat model and its children.
        """
        ret = []
        try:
            if isinstance(self, typeName):
                ret.append(self)
            # for c in self.children:
            #     ret = ret + c.getAllDownByType(typeName)

            for attr_name in dir(self):
                if attr_name.startswith('_'):
                    continue
                # Avoid calling properties that may raise or are not data attributes
                try:
                    attr = getattr(type(self), attr_name, None)
                    if isinstance(attr, property):
                        continue
                    attr = getattr(self, attr_name)
                except Exception:
                    continue
                # Avoid calling methods
                if callable(attr):
                    continue
                if isinstance(attr, list):
                    for item in attr:
                        if isinstance(item, typeName):
                            ret.append(item)
                        elif isinstance(item, BaseThreatModelObject):
                            # Avoid infinite recursion
                            if item is not self:
                                ret = ret + item.getAllDownByType(typeName)
        except:
            raise BaseException(f"Error getting all down by type {typeName} in {self.id}")

        return ret

    #get something by ID inside a specific TM object
    def getDescendantById(self, id):
        if not hasattr(self, 'children'):
            return None
        for x in self.children:
            if x._id == id:
                return x
        for x in self.children:
            res = x.getDescendantById(id)
            if res != None:
                return res
        return None

    def getRoot(self):
        if (self.parent == None):
            return self
        else:
            return self.parent.getRoot()
        
    #get an object by ID inside a TM and all its children 
    def getDescendantFirstById(self, id):
        res = self.getDescendantById(id)
        if res != None:
                return res
        if not hasattr(self, 'childrenTM'):
            return self.getDescendantById(id)
        for tm in self.childrenTM:
            res = tm.getDescendantFirstById(id)
            if res != None:
                return res
        return None

class REFID(BaseThreatModelObject):
    """
    This is a reference to an object in the threat model.
    It is used to link objects together, e.g. a countermeasure to a threat.
    """
    def __init__(self, dict, parent):
        super().__init__(dict, parent)
        if "REFID" not in dict:
            raise BaseException("REFID needs to be defined in: "+self.id)
        self._id = "REFID_"+ dict["REFID"]
        # Store REFID in a map by ID on the root element
        root = self.getRoot()
        if not hasattr(root, "_refid_map"):
            root._refid_map = {}
        root._refid_map[self._id] = self
    
    def resolve(self):
        """
        Resolve the REFID to the actual object in the threat model.
        """
        root = self.getRoot()
        # refid = self._id.replace("REFID_", "")
        return root.getDescendantFirstById(self.REFID)
    
    def replaceInParent(self, copyReferenced=True):
        
        """
        Replace the REFID in the parent object with the actual object.
        """
        referenced = self.resolve()
        if copyReferenced:
            # if copyReferenced is True, we copy the referenced object
            # this is useful to avoid modifying the original object
            referenced = copy.copy(referenced)
            referenced.isReference = True
        if hasattr(self.parent, 'children'):
            if self in self.parent.children:
                self.parent.children.remove(self)
                self.parent.children.add(referenced)
        
        replaced = False
        for attr_name in dir(self.parent):
            if attr_name.startswith('_'):
              continue
            # Avoid calling properties that may raise or are not data attributes

            attr = getattr(type(self.parent), attr_name, None)
            if isinstance(attr, property):
                continue
            attr = getattr(self.parent, attr_name)

            # Avoid calling methods
            if callable(attr):
                continue

            attr = getattr(self.parent, attr_name)
            if isinstance(attr, list):
                # Replace all occurrences of self in the list
                while self in attr:
                    attr[attr.index(self)] = referenced
                    replaced = True

        if not replaced:
             raise BaseException("Could not replace REFID in parent: " + self.id)

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

        # return ["red","orange","yellow","green"][index]

    def getSmartScoreVal(self):
        index = self.getSmartScoreIndex()
        ret = self.scores()[index]
        return ret
    
    def getSmartScoreSeverity(self):
        index = self.getSmartScoreIndex()
        ret = self.severities()[index]
        return ret

class SecurityObjective(BaseThreatModelObject):

    _treeImage = True

    priority = "High"

    inScope = True


    @property
    def treeImage(self):
        # if there are not direct threats do not show the empty tree
        for threat in self.getRoot().getAllDown('threats'):
            for impactedSecObj in threat.impactedSecObjs:
                if impactedSecObj.id == self.id: 
                     return self._treeImage
        return False
    
    @treeImage.setter
    def treeImage(self, treeImage):
        self._treeImage = treeImage
    
    def __init__(self):
        return
    def __init__(self, dict, parent):
        # self.threats: list[Threat] = []
    
        # if "ID" in dict and dict["ID"] is not None and "." in dict["ID"]:
        #     dict["ID"] = dict["ID"].replace(".","_").upper()

        self.contributesTo = []

        self.parent = parent
        if hasattr(parent, "children"):
            parent.children.add(self)
        else:
            parent.children = {self}

        self.scope=parent
        self.parent=parent
        self.id = str(dict["ID"])
        for k, v in dict.items():
            if k == "contributesTo":
                    references = dict["contributesTo"]
                    for dict2 in references:
                        if "REFID" in dict2:
                            self.contributesTo.append(REFID(dict2, self))
                            # refID = dict2['REFID']
                            # referenced = self.getRoot().getDescendantFirstById(refID)
                            # if referenced == None:
                            #     raise BaseException("REFID: "+ dict2['REFID'] +" not found in: "+self.id )
                            # copiedObject  = copy.copy(referenced)
                            # copiedObject.isReference = True
                            # self.contributesTo.append(copiedObject)
            else:
                setattr(self, k, v)

    def linkedImpactMDText(self):
        return  f"<code><a href=\"#{self.anchor}\">{self._id}</a></code>"
    
    def contributedToMDText(self):
        return  f"<code><a href=\"#{self.anchor}\">{self._id}</a></code> *({self.title})*"
    
    def printAsText(self):
        return "\nID: " + self.id + " \nDescription: " + self.description 
    
    def shortText(self):
        firstPara = self.description.split("\n")[0]
        return f"*{self.id}*\n({firstPara})" 

class Scope(BaseThreatModelObject):
    pass
        
class Countermeasure(BaseThreatModelObject):
    def __init__(self):
        return
    def __init__(self, dict, threat):

        self.originDict = dict

        parent = threat
        if hasattr(parent, "children"):
            parent.children.add(self)
        else:
            parent.children = {self}

        self.threat=threat
        self.parent=threat
        # if "ID" in dict and dict["ID"] is not None and "." in dict["ID"]:
        #     dict["ID"] = dict["ID"].replace(".","_").upper()
        self.id = str(dict["ID"])



        if "inPlace" not in dict.keys():
            raise BaseException(f"Countermeasure {self.id} needs an 'inPlace' attribute True or False")
        if "public" not in dict.keys():
            raise BaseException(f"Countermeasure {self.id} needs an 'public' attribute True or False")

        for k, v in dict.items():
            setattr(self, k, v)

    def printAsText(self):
        return "\nID: " + self.id + " \nDescription: " + self.description 
    
    def RAGStyle(self):
        if not hasattr(self, "inPlace"):
            return "countermeasureNIP"
        if self.inPlace:
            return "countermeasureIP"
        return "countermeasureNIP"

    def statusColors(self):
        
        inPlace = { 'border':'#82B366', 'fill':'#D5E8D4'}
        notInPlace = { 'border':'#D6B656', 'fill':'#FFF2CC'}

        if not hasattr(self, "inPlace"):
            return notInPlace
        if self.inPlace:
            return inPlace
        return notInPlace
    
    #default value
    operational = False

    _operator = "UNDEFINED"
    @property
    def operator(self):
        return self._operator
    @operator.setter
    def operator(self, operator):
        if operator:
            self._operator = operator

        
class Threat(BaseThreatModelObject):

    @property
    def ticketLink(self):
        # if self.public:
        #     return None
        return getattr(self, '_ticketLink', None)
    
    @ticketLink.setter
    def ticketLink(self, value):
        self._ticketLink = value
        if( hasattr(self.originDict, 'insert') and not 'ticketLink' in self.originDict ): # it may be not an ordered  dict (with insert method) as in ruaml yaml parser
            self.originDict.insert(1, 'ticketLink', value) #gives a nice order on roundtrip yaml file update
        else:
            self.originDict.update({'ticketLink': value})
            
    @property
    def description(self):
        if hasattr(self, 'attack'):
            return "**Attack:** " + self.attack + "<br/> **Impact:** " + self.impactDesc
        else:
            return "undefined"
        
    @property
    def attack_desc(self):
        if hasattr(self, 'attack'):
            return self.attack
        else:
            return None
        
    @property
    def impact_desc(self):
        ret = ""
        if hasattr(self, 'impactDesc'):
            ret +=   self.impactDesc  + "<br/> "
        if self.impactedSecObjs:
            # ret = ret + "<br/> "
            secObj: SecurityObjective 
            for secObj in self.impactedSecObjs:
                try:
                    ret += secObj.linkedImpactMDText() + "<br/> "
                except:
                    raise Exception(f"Problem in impactedSecObj definition reference in {secObj.id} " )  

        return ret

    @property
    def title(self):
        if hasattr(self, '_title'):
            return self._title
        else:
            return self.threatGeneratedTitle()
    
    @title.setter
    def title(self, value):
        self._title = value
    
    def getSmartScoreDesc(self):
        if self.cvssObject:
            return self.cvssObject.getSmartScoreDesc()
        else:    
            return "TODO CVSS"

    def getSmartScoreVal(self):
        if self.cvssObject:
            return self.cvssObject.getSmartScoreVal()
        else:    
            return 0.0

    def getSmartScoreColor(self):
        if self.cvssObject:
            return self.cvssObject.getSmartScoreColor()
        else:    
            return "gray"


    def threatGeneratedTitle(self):
        assetDesc = " in: "
        if hasattr(self, 'assets'):
            if len(self.assets) > 0:
                for asset in self.assets:
                    assetDesc+= f"{asset.type} {asset.title}, "
                return self.threatType + assetDesc[:-2]
            else:
                return self.threatType
        else:
            return self.threatType

    @property
    def operational(self):
        for cm in self.countermeasures:
            if cm.operational:
                return True
        return False

    def getOperationalCountermeasures(self):
        ocmList = []
        for cm in self.countermeasures:
            if cm.operational:
                ocmList.append(cm)
        return ocmList

    def __init__(self):

        return
    def __init__(self, dict, tm, public=False):

        self.originDict = dict

        parent = tm
        if hasattr(parent, "children"):
            parent.children.add(self)
        else:
            parent.children = {self}

        self.countermeasures = []
        self.assets = []
        self.impactedSecObjs = []
        self.attackers = []

        self.parent = tm 
        self.threatModel = tm

        self.id = dict["ID"]
       
        dict.setdefault('CVSS', {'base':'TODO CVSS', 'vector':''})
        dict.setdefault('fullyMitigated', False)

            
        for k, v in dict.items():
            if k == "ticketLink":
                if public:
                    pass
                else:
                    setattr(self, k, v)
            elif k == "countermeasures":
                for cmData in v:
                    if self.filterOutForPublicOrVersions(public, cmData):
                        pass
                    else:
                        if "ID" in cmData:
                            self.countermeasures.append(Countermeasure(cmData, self))
                        elif "REFID" in cmData:

                            self.countermeasures.append(REFID(cmData, self))

                        else:
                            raise BaseException("REFID or ID needed to define a countermeasure in: "+self.id )

            elif k == 'impactedSecObj':
                for cmData in v:
                    try:
                        if "REFID" in cmData:

                            self.impactedSecObjs.append(REFID(cmData, self))
                        else:
                            raise BaseException("REFID needed to reference an impacted Security Objective in: "+self.id )
                    except: 
                        raise BaseException(f"Problem in impactedSecObj definition reference in {self.id}, try using correct \"- REFID: \" " )

            elif k == "assets":
                if v is not None:
                    for assetData in v:
                        try:
                            # self.assets.append(tm.getAssetById(assetData["REFID"])) 
                            self.assets.append(REFID(assetData, self))
                        except:
                            raise BaseException("reference To asset ID, REFID not found  in: "+self.id )
            
            elif k == "attackers":
                for attackerData in v:
                    try:
                        if "REFID" in attackerData:

                            self.attackers.append(REFID(attackerData, self))
                        else:
                            raise BaseException("REFID needed to reference an actual attacker ID in: "+self.id )
                    except: 
                        raise BaseException(f"Problem in attacker definition reference in {self.id}, try using correct \"- REFID: \" " )

            else:
                try:
                    setattr(self, k, v)
                except:
                    raise BaseException(f"cannot set attribute {k} on {self.__class__}: {self.id} ")
            
        if not hasattr(self, "threatType"):
            raise BaseException(f"threatType required for {self.id}")

        #set defaults for CVSS
        if self.CVSS['vector']:
            try:
                self.cvssObject = TMCVSS(self.CVSS['vector'])
            except:
                raise BaseException(f"Malformed CVSS vector in {self.id}" )
        else:
            self.cvssObject = None

    def hasOperationalCountermeasures(self):
        for cm in self.countermeasures:
            if cm.operational:
                return True
        return False

    def printAsText(self):
        return "\nID: " + self.id + " \nDescription: " + self.description


class Asset(BaseThreatModelObject):

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
            return 'Yes' if self._inScope else 'No'
        except:
            raise BaseException("asset "+ self.id +" missing valid boolean inScope attribute " )
    @inScope.setter
    def inScope(self, value):
        if not isinstance(value, bool):
            raise TypeError('Asset.inScope must be an boolean' + ", found value: " + value + " in " + self.id)
        self._inScope = value
    
    def __init__(self, dict, parent):
        super().__init__(dict, parent)
        if 'type' not in dict:
            raise ValueError(f"Asset {self.id} must have a 'type' property")
            
        if 'inScope' not in dict or not isinstance(dict['inScope'], bool):
            raise ValueError(f"Asset {self.id} must have a boolean 'inScope' property")
        for k, v in dict.items():
            setattr(self, k, v)

class Attacker(BaseThreatModelObject):
    def __init__(self, dict, parent):
        super().__init__(dict, parent)
        if not hasattr(self, 'title'):
            raise BaseException(f"Attacker {self.id} must have a title")
        for k, v in dict.items():
            setattr(self, k, v)

class Assumption(BaseThreatModelObject):
    pass

class ThreatModel(BaseThreatModelObject):

    def dumpRecursive(self, folder=None, prefix="", encoding="utf-8", recursive=True):
        
        originalFolder, fn = os.path.split(self.fileName)

        if folder is None:
            folder = originalFolder
        fn = prefix + fn
        path = folder + os.path.sep +  fn
        outputStream = open(path, "wt", encoding=encoding)
        
        print (f"...dumping yaml file: {path}")
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.dump(self.originDict, outputStream)

        if recursive:
            for childrenTM in self.childrenTM:
                childrenTM.dumpRecursive(prefix=prefix, encoding=encoding, recursive=recursive)

    def assetDir(self):
        return os.path.dirname(self.fileName)+ "/assets"
    def __init__(self):
        return
    def __init__(self, fileIn, parent = None, public=False, versionsFilterStr = None):

        if versionsFilterStr == None:      
            self._versionsFilter = None
        else:
            self._versionsFilter = list(semantic_version.Version.coerce(v) for v in versionsFilterStr.split(","))
            self.versionsFilterStr = versionsFilterStr #Populate for template only
        self.fileName = fileIn.name

        print ("processing:" + fileIn.name)
        fileIn.seek(0)
        if not fileIn.name.endswith('.yaml'):
            print("input file needs to be .yaml")
            exit(-2)

        #tmDict = yaml.load(fileIn)
        tmDict = try_load_threatmodel_yaml(fileIn.name)
        
        self.originDict = tmDict

        self.childrenTM = []

        #Parent First (this is recursive)
        if parent is None:
                self.parent = None
        else:
            parent.childrenTM.append(self)
            self.parent = parent

        self.threats: list[Threat] = []
        self._id = tmDict["ID"]
        if tmDict["scope"] is None:
            raise BaseException(f"Scope is empty in {self.id}, please check the threat model file")
        self.scope = Scope(tmDict["scope"], self)
        self.analysis = tmDict["analysis"]
        self.assets: list[Asset]  = []
        self.securityObjectives: list[SecurityObjective]  = []
        self.attackers: list[Attacker] = []
        self.assumptions: list[Assumption] = []


        for scope_k, scope_v in tmDict['scope'].items():    
            if "securityObjectives" == scope_k:
                try:
                    if scope_v is not None:
                        for secObjectiveDict in scope_v:
                            secObjective = SecurityObjective(secObjectiveDict, self)
                            self.securityObjectives.append(secObjective)               
                except:
                    raise

            elif "assets" == scope_k:
                try:
                    if scope_v is not None:
                        for assetDict in scope_v:
                            if assetDict  is None:
                                raise BaseException(f"Asset is 'None' in {self.id}")
                            if self.filterOutForPublicOrVersions(public, assetDict):
                                pass
                            else:
                                asset = Asset(assetDict, self)
                                self.assets.append(asset)               
                except:
                    raise
        
            elif "attackers" == scope_k:
                try:
                    for assetDict in scope_v:
                        asset = Attacker(assetDict, self)
                        self.attackers.append(asset)
                except TypeError as te:
                    # print(self.id + ' has no attackers defined')
                    pass
            elif "assumptions" == scope_k:
                try:
                    for assumptionDict in scope_v:
                        assumption = Assumption(assumptionDict, self)
                        self.assumptions.append(assumption)
                except TypeError as te:
                    # print(self.id + ' has no assumptions defined')
                    pass

        for k, v in tmDict.items():
            if k == "scope" or k == "parent":
                pass

            elif k == "title":
                self._title=tmDict['title']

            elif "threats"  == k:
                if  tmDict["threats"] != None:
                    for threatDict in tmDict["threats"]:
                        print("Parsing threat: "+ threatDict['ID'])
                        if self.filterOutForPublicOrVersions(public, threatDict):
                            pass
                        else:
                            threat = Threat(threatDict, self, public=public)
                            self.threats.append(threat)
                
            elif "children"  == k:
                for childrenDict in tmDict['children']:
                    try:
                        child_id = childrenDict['ID']
                        base_path = os.path.dirname(fileIn.name)
                        if child_id.endswith('.yaml'):
                            childrenFilename = os.path.join(base_path, child_id)
                        else:
                            childrenFilename = os.path.join(base_path, child_id, child_id + ".yaml")
                    except Exception as e:
                        print(f"Error processing child threat model: {e}")
                        raise BaseException(f"Error processing child threat models (check if children is an array e.g. - ID: ...)")
                    
                    childTM = ThreatModel(open(childrenFilename, encoding="utf-8-sig"),
                        parent=self, public=public, versionsFilterStr=versionsFilterStr)


            elif "gantt"  == k:
                self.gantt=tmDict['gantt']

            else:
                try:
                    setattr(self, k, v)
                except:
                    raise BaseException(f"cannot set attribute {k} on {self.__class__}: {self.id} ")

        

        if self.isRoot():
            # resolve REFIDs in the threat model
            # Replace all objects of type REFID in the threat model tree
            for ref in self.getAllDownByType(REFID):
                try:
                    ref: REFID
                    ref.replaceInParent(copyReferenced=True)
                except Exception as e:
                    raise BaseException(f"Error replacing REFID {ref.id} in threat model {self.id}: {e}")
            

            self.checkThreatModelConsistency()

    def checkThreatModelConsistency(self):
        """
        Check the consistency of the threat model.
        This includes checking the following:
        - If a threat is fully mitigated, at least one mitigation should be 'inPlace' true.
        - If a threat is not fully mitigated, there should be no mitigation 'inPlace' true.
        - If a threat is public = true, the threat should be fully mitigated.
        - If a threat is fully mitigated and public, at least one countermeasure should be 'inPlace' true and public = true.
        """
        ##############
        # Check the consistency of the threat model
        ##############
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


    def printAsText(self):
        return "\nID: " + self._id + " \nDescription: " + self.description 
    
    def getAllAttackers(self):
        if self.parent is None:
            return self.attackers
        else:
            return self.parent.getAllAttackers() + self.attackers

    def isRoot(self):
        return self.parent == None
    
    def getChildrenById(self, id):
        for x in self.children:
            if x._id == id:
                return x
    def getThreatsByFullyMitigated(self, fullyMitigated ):
        ts = [t for t in self.getAllDown('threats') if t.fullyMitigated is fullyMitigated]
        ret =  sorted(ts, key=lambda x: x.getSmartScoreVal(), reverse=True )
        return  ret
    
    def getThreatsByFullyMitigatedAndOperational(self, fullyMitigated, operational ):
        ts = [t for t in self.getAllDown('threats') if (t.fullyMitigated is fullyMitigated and t.operational is operational)]
        ret =  sorted(ts, key=lambda x: x.getSmartScoreVal(), reverse=True )
        return ret

    def getAssetsByProps(self, **kwargs ):
        res = [asset for asset in self.getAllDown('assets') if matchesAllPros(asset , **kwargs)]
        return res
        
    def getOperationalGuideData(self):

        guideData = {}

        ts = [t for t in self.getAllDown('threats') if (t.operational is True)]
        ts =  sorted(ts, key=lambda x: x.getSmartScoreVal(), reverse=True )

        # extract all countermeasures

        cms = []
        operators = set()
        for t in ts:
            for c in t.countermeasures:
                if not c.isReference and c.operational:
                    cms.append(c)
                    # extract all operators
                    operators.add(c.operator)

        # associate countermeasure with operator
        for op in operators:
            guideData[op]=[]

        for countermeasure in cms:
            guideData[countermeasure.operator].append(countermeasure)

        return guideData

    def getAssetById(self, id):
        if id is None:
             raise Exception("Asset ID not found in "+ self._id)
        for x in self.getAllUp('assets'):
            if x._id == id:
                return x
        raise Exception("Asset with ID not found in "+ self._id+ ": " + id)
    
    def getById(self, id):
        return self.getRoot().getDescendantFirstById(id)

    def getChildrenTMbyID(self, id):
        return next((tmo for tmo in self.childrenTM if tmo._id == id), None)
    
    def getDescendants(self):
        descendants = []
        for child in self.childrenTM:
            descendants.append(child)
            descendants.extend(child.getDescendants())
        return descendants
    @property
    def title(self):
        if not hasattr(self, '_title'):
            return self._id.replace('_', ' ')
        else:
            return self._title
    @title.setter
    def title(self, value):
        self._title = value

    def get_ISO27001_groups_titles(self):
        """
        Returns a list of unique group descriptions found in the policy items.

        Returns:
            list: A list of strings, where each string is a unique group description.
        """
        group_descriptions = set()
        for item in self.ISO27001Ref:
            # Ensure 'group' key exists to prevent errors on malformed data
            if isinstance(item, dict) and 'group' in item:
                 group_descriptions.add(item['group'])
            # Optional: Handle/log items that are not dictionaries or lack 'group'
            # else:
            #     print(f"Warning: Skipping item {item} as it's not a valid policy dictionary.")


        return list(group_descriptions)


    def get_ISO27001_grouped_ids(self):
        """
        Returns a dictionary mapping group descriptions to a list of their
        associated policy IDs.

        Returns:
            dict: A dictionary where keys are group descriptions (str)
                  and values are lists of policy IDs (list of str).
        """
        # Use defaultdict for simpler appending
        group_ids_dict = defaultdict(list)

        for item in self.ISO27001Ref:
             # Ensure 'group' and 'ID' keys exist
            if isinstance(item, dict) and 'group' in item and 'ID' in item:
                group = item['group']
                item_id = item['ID']
                group_ids_dict[group].append(item_id)
            # Optional: Handle/log malformed items as above

        # Convert defaultdict to a regular dict before returning if preferred,
        # though defaultdict often works fine downstream.
        return dict(group_ids_dict)


def try_load_threatmodel_yaml(filename):
    try:
        tm = yaml.load(open(filename, encoding="utf-8-sig"))#safe_load(open(filename))
        return tm
    except YAMLError as exc:
        print ("Error while parsing YAML file:")
        if hasattr(exc, 'problem_mark'):
            if exc.context != None:
                print ('  parser says\n' + str(exc.problem_mark) + '\n  ' +
                    str(exc.problem) + ' ' + str(exc.context) +
                    '\nPlease correct data and retry.')
            else:
                print ('  parser says\n' + str(exc.problem_mark) + '\n  ' +
                    str(exc.problem) + '\nPlease correct data and retry.')
        else:
            print ("Something went wrong while parsing yaml file")
        raise exc

    except Exception as e:
        print(f'Error reading: {filename}')
        print(f'Exception: { e.__class__.__name__}')
        offending = e.object[e.start:e.end+32]
        print("This file isn't encoded with", e.encoding)
        print("Illegal bytes:", repr(offending))
        print(e)
        print('-'*80)
        raise e
