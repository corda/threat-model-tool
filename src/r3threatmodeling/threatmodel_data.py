"""
R3 Threat Modeling 
"""

"""
    
"""
from xml.etree.ElementPath import get_parent_map
from ruamel.yaml import YAML
#import yaml
yaml=YAML(typ='rt')

import os
import re
from io import StringIO
import html
import copy
from cvss import CVSS3


class BaseThreatModelObject:

    originDict= None

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
            return self._id
    @id.setter
    def id(self, id):
        self._id = id

    isReference = False 
      
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

        self.originDict = dict

        self.description = "undefined"
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

    def getAllDown(self, attrName):
        ret = getattr(self, attrName, [])
        for c in self.childrenTM:
            ret = ret + c.getAllDown(attrName)
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

    def getDescendantFirstById(self, id):
        res = self.getDescendantById(id)
        if res != None:
                return res
        if not hasattr(self, 'childrenTM'):
            return self.getDescendantById(id)
        for tm in self.childrenTM:
            res = tm.getDescendantById(id)
            if res != None:
                return res
        return None
    
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

class SecurityObjective(BaseThreatModelObject):
    def __init__(self):
        return
    def __init__(self, dict, parent):
        # self.threats: list[Threat] = []

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
                            refID = dict2['REFID']
                            referenced = self.getRoot().getDescendantFirstById(refID)
                            if referenced == None:
                                raise BaseException("REFID: "+ dict2['REFID'] +" not found in: "+self.id )
                            copiedObject  = copy.copy(referenced)
                            copiedObject.isReference = True
                            self.contributesTo.append(copiedObject)
            else:
                setattr(self, k, v)

    def linkedImpactMDText(self):
        return  f"Compromised <code><a href=\"#{self.id}\">{self._id}</a></code>: {self.title}"
    
    def contributedToMDText(self):
        return  f"Contributes to <code><a href=\"#{self.id}\">{self._id}</a></code> *({self.title})*"
    
    def printAsText(self):
        return "\nID: " + self.id + " \nDescription: " + self.description 

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
        self.id = str(dict["ID"])

        if "inPlace" not in dict.keys():
            raise BaseException(f"Countermeasure {self.id} needs an 'inPlace' attribute True or False")

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
    
    #default value
    operational = False
      

        
class Threat(BaseThreatModelObject):

    @property
    def ticketLink(self):
        return self._ticketLink
    
    @ticketLink.setter
    def ticketLink(self, value):
        self._ticketLink = value
        if( hasattr(self.originDict, 'insert') and not 'ticketLink' in self.originDict ): # it may be not an ordered  dict (with insert method) as in ruaml yaml parser
            self.originDict.insert(1, 'ticketLink', value) #gives a nice order on roundtrip yaml file update
        else:
            self.originDict.update({'ticketLink': value})
            

    
    @property
    def description(self):
        if hasattr(self, 'attack') and hasattr(self, 'impact'):
            return "**Attack:** " + self.attack + "<br/> **Impact:** " + self.impact
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
        if self.impacts:
            secObj: SecurityObjective 
            for secObj in self.impacts:
                ret += secObj.linkedImpactMDText()+ "<br/> "
        if hasattr(self, 'impact'):
            ret += self.impact + "<br/> "
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
        assetDesc = " in "
        if hasattr(self, 'assets'):
            if len(self.assets) > 0:
                for asset in self.assets:
                    assetDesc+= asset.title + ", "
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
    def __init__(self, dict, tm):

        self.originDict = dict

        parent = tm
        if hasattr(parent, "children"):
            parent.children.add(self)
        else:
            parent.children = {self}

        self.countermeasures = []
        self.assets = []
        self.impacts = []
        self.attackers = []

        self.parent = tm 
        self.threatModel = tm

        self._id = dict["ID"]
        
        dict.setdefault('CVSS', {'base':'TODO CVSS', 'vector':''})
        dict.setdefault('fullyMitigated', False)

        for k, v in dict.items():
            if k == "countermeasures":
                for cmData in v:
                    if "ID" in cmData:
                        self.countermeasures.append(Countermeasure(cmData, self))
                    elif "REFID" in cmData:
                        refID = cmData['REFID']
                        referencedCM = self.getRoot().getDescendantFirstById(refID)
                        if referencedCM == None:
                            raise BaseException("REFID: "+ cmData['REFID'] +" not found in: "+self.id )
                        copiedObject  = copy.copy(referencedCM)
                        copiedObject.isReference = True
                        self.countermeasures.append(copiedObject)
                    else:
                        raise BaseException("REFID or ID needed to define a countermeasure in: "+self.id )

            elif k == "impacts":
                for cmData in v:
                    try:
                        if "REFID" in cmData:
                            refID = cmData['REFID']
                            referenced = self.getRoot().getDescendantFirstById(refID)
                            if referenced == None:
                                raise BaseException("REFID: "+ cmData['REFID'] +" not found in: "+self.id )
                            copiedObject  = copy.copy(referenced)
                            copiedObject.isReference = True
                            self.impacts.append(copiedObject)
                        else:
                            raise BaseException("REFID needed to reference an impacted Security Objective in: "+self.id )
                    except: 
                        raise BaseException(f"Problem in impacts definition reference in {self.id}, try using correct \"- REFID: \" " )

            elif k == "assets":
                if v is not None:
                    for assetData in v:
                        try:
                            #TODO rename to REFID
                            self.assets.append(tm.getAssetById(assetData["ID"])) 
                        except:
                            raise BaseException("reference To asset ID "+v[0]['ID']+" not found  in: "+self.id )
            
            elif k == "attackers":
                for attackerData in v:
                    try:
                        if "REFID" in attackerData:
                            refID = attackerData['REFID']
                            referenced = self.getRoot().getDescendantFirstById(refID)
                            if referenced == None:
                                raise BaseException("REFID: "+ attackerData['REFID'] +" not found in: "+self.id )
                            copiedObject  = copy.copy(referenced)
                            copiedObject.isReference = True
                            self.attackers.append(copiedObject)
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
    

class Attacker(BaseThreatModelObject):
    pass
class Assumption(BaseThreatModelObject):
    pass



class ThreatModel(BaseThreatModelObject):

    def dumpRecursive(self, folder=None, prefix=""):
        
        originalFolder, fn = os.path.split(self.fileName)

        if folder is None:
            folder = originalFolder
        fn = prefix + fn
        path = folder + os.path.sep +  fn
        outputStream = open(path, "wb")
        print (f"...dumping yaml file: {path}")
        yaml.indent(mapping=2, sequence=4, offset=2)
        yaml.dump(self.originDict, outputStream)

        for childrenTM in self.childrenTM:
            childrenTM.dumpRecursive(folder, prefix)

    def __init__(self):
        return
    def __init__(self, fileIn, parent = None):

        self.fileName = fileIn.name

        print ("processing:" + fileIn.name)
        fileIn.seek(0)
        if not fileIn.name.endswith('.yaml'):
            print("input file needs to be .yaml")
            exit -2   
        tmDict = yaml.load(fileIn)
        
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
                    print(self.id + ' has no attackers defined')
                    pass
            elif "assumptions" == scope_k:
                try:
                    for assumptionDict in scope_v:
                        assumption = Assumption(assumptionDict, self)
                        self.assumptions.append(assumption)
                except TypeError as te:
                    print(self.id + ' has no assumptions defined')
                    pass

        for k, v in tmDict.items():
            if k == "scope" or k == "parent":
                pass

            elif k == "title":
                self._title=tmDict['title']

            elif "threats"  == k:
                if  tmDict["threats"] != None:
                    for threatDict in tmDict["threats"]:
                        threat = Threat(threatDict, self)
                        self.threats.append(threat)
                
            elif "children"  == k:
                for childrenDict in tmDict['children']:
                    childTM = ThreatModel(
                        fileIn= open( os.path.dirname(fileIn.name)  + os.path.sep +  childrenDict['ID'] +".yaml"),
                        parent = self)

            elif "gantt"  == k:
                self.gantt=tmDict['gantt']

            else:
                try:
                    setattr(self, k, v)
                except:
                    raise BaseException(f"cannot set attribute {k} on {self.__class__}: {self.id} ")

    def printAsText(self):
        return "\nID: " + self._id + " \nDescription: " + self.description 
    
    def getAllAttackers(self):
        if self.parent is None:
            return self.attackers
        else:
            return self.parent.getAllAttackers() + self.attackers

    def getAllAssets(self):
        if self.parent is None:
            return self.assets
        else:
            return self.parent.getAllAssets() + self.assets

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

    def getAllThreatsByFullyMitigated(self, fullyMitigated ):
        return  [t for t in self.getAllThreats() if t.fullyMitigated is fullyMitigated]

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
        if len(self.childrenTM) == 0:
            return []
        else:
            descendants = list()
            for child in self.childrenTM:
                 descendants += child.getDescendants()
            return self.childrenTM + descendants
    @property
    def title(self):
        if not hasattr(self, '_title'):
            return self._id.replace('_', ' ')
        else:
            return self._title
    @title.setter
    def title(self, value):
        self._title = value