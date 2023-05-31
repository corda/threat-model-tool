"""
R3 Threat Modeling 
"""

"""
    
"""
from xml.etree.ElementPath import get_parent_map
from ruamel.yaml import YAML
#import yaml

yaml=YAML(typ='rt')
from mako.template import Template
from mako.runtime import Context
from yaml.loader import SafeLoader
import os
from mako.exceptions import RichTraceback
from mako.lookup import TemplateLookup
import re
import markdown
from markdown import Markdown
from io import StringIO
import ntpath
import html
import copy
from cvss import CVSS3



#example from https://stackoverflow.com/questions/761824/python-how-to-convert-markdown-formatted-text-to-text

def unmark_element(element, stream=None):
    if stream is None:
        stream = StringIO()
    if element.text:
        stream.write(element.text)
    for sub in element:
        unmark_element(sub, stream)
    if element.tail:
        stream.write(element.tail)
    return stream.getvalue()


# patching Markdown
Markdown.output_formats["plain"] = unmark_element
__md = Markdown(output_format="plain")
__md.stripTopLevelTags = False


def markdown_to_text(text):
    return __md.convert(text)

def mermaid_escape(text):
    # if text is None:
    #     return "XXX_NONE_OBJECT"
    text = re.sub(r"\(RFI[\s:]*(.*)\)", "", text)
    return html.escape(markdown_to_text(text).replace("\"","#quot;")).replace("(", "&lpar;").replace(")", "&rpar;")

def valueOr(o, a, alt):
    if hasattr(o, a ):
        ret =  getattr(o, a)
        return ret
    else:
        return alt

# class ThreatModel:
#     parent = ""
#     prefix = ""
#     def __init__(self):
#         return


from fileinput import filename

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

        self.markdown_to_text = markdown_to_text

        self.description = "undefined"
        self.parent = parent

        if hasattr(parent, "children"):
            parent.children.add(self)
        else:
            parent.children = {self}

        self._id = dict["ID"]

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
        # if not hasattr(self, 'children'):
        #     return getattr(self, attrName, [])
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
        # for tm in self.childrenTM:
        #     res = tm.getFirstById(id)
        #     if res != None:
        #         return res


    def mermaid_escaped_prop(self, propName):
        return mermaid_escape(getattr(self, propName))

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

    # def getScoresMap(self):
    #     map = {
    #         "Base score":  self.getScores()[0],
    #         "Temporal score":  self.getScores()[1],
    #         "Temporal score":  self.getScores()[2]
    #         }
    #     return ("Base score", "Temporal score", "Temporal score"), self.getScores()

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

class Scope():
    # description = "undefined"
    # title = "undefined"
    securityObjective = []

    def __init__(self):
        return
    def __init__(self, dict):

        self.originDict = dict

        for k, v in dict.items():
        # if k == "securityObjective":
        #     self.securityObjectives.append(SecurityObjective(v))
        # else:
            setattr(self, k, v)


    def printAsText(self):
        return "\nID: " + self.id + " \nDescription: " + self.description 

    @property
    def fmtdescription(self):
        import re
        return re.sub('(?<![\r\n])(\r?\n|\n?\r)(?![\r\n])', ' ', self.description)
        


    
class Countermeasure(BaseThreatModelObject):
    def __init__(self):
        return
    def __init__(self, dict, threat):
        # self.threats: list[Threat] = []

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
        
    def getAttackDescForMermaid(self):
        try:
            if len(self.attack) >= 290:
                return mermaid_escape(self.attack)[:290]+ "[...]"
            else:
                return mermaid_escape(self.attack)
        except:
            raise BaseException(f"Threat {self.id} needs attack attribute")

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
        # if not self.impacts and not hasattr(self, 'impact'):
        #     return None
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

        # if not "fullyMitigated" in dict:
        #     #default to False
        #     dict['fullyMitigated'] = False
        
        dict.setdefault('CVSS', {'base':'TODO CVSS', 'vector':''})
        dict.setdefault('fullyMitigated', False)

        for k, v in dict.items():
            # if k == "title":
            #     self._title=dict['title']
            # el
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
    
    # scope: Scope

    # id = "undefined" 
    # analysis: str
    # threats = []

    # parent = None

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
            # if "parent" in dict:
            #     self.parent = ThreatModel(dict["parent"])
            #     self.parent.childrenTM.append(self)
            # else:
                self.parent = None
        else:
            parent.childrenTM.append(self)
            self.parent = parent

        self.threats: list[Threat] = []
        self._id = tmDict["ID"]
        self.scope = Scope(tmDict["scope"])
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
    
    # def getAllThreats(self):
    #     if self.parent is None:
    #         return self.threats
    #     else:
    #         return self.parent.getAllThreats() + self.threats

    def getAllThreatsByFullyMitigated(self, fullyMitigated ):
        return  [t for t in self.getAllThreats() if t.fullyMitigated is fullyMitigated]

            

    def getAssetById(self, id):
        if id is None:
             raise Exception("Asset ID not found in "+ self._id)
        for x in self.getAllUp('assets'):
            if x._id == id:
                return x
        raise Exception("Asset with ID not found in "+ self._id+ ": " + id)

    # def getAttackerById(self, id):
    #     if id is None:
    #          raise Exception("Attacker ID not found in "+ self._id)
    #     for x in self.getAllUp('attackers'):
    #         if x._id == id:
    #             return x
    #     raise Exception("Attacker with ID not found in "+ self._id+ ": " + id)
    
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
    
    # def merge (self, tmo):
    #     #merge from the root, self is the target

    #     #TODO find common ancestor iterating target chain (self), if not found (two different roots then error)
    #     #make it recursive

    #     if self.parent._id == tmo.parent._id:
    #         self.childrenTM.update(tmo.children)
    #     else:
    #         self.parent.



    #     #if parent is the same 
    #         #them merge
    #         #if different parent 
    #             #find common parent, even None/Root
    #     #else (same parent) 
    #         #merge/union children

        
    #     return None

def printAllThreats(tm, indent):

    tm.setdefault('threats', [])
    print("-"*indent + "+ " + tm["ID"])

    for threat in tm["threats"]:
        #print( "-"*indent + "+Threat: " +    str(threat))
        t = Threat(threat)
        print( "-"*indent + " Threat: " + t.printAsText())
        for cm in t.countermeasures:
            print(print( "-"*indent + "  Countermeasure: " + cm.printAsText()) )
    return


def printIndentedID(tm, indent):
    print("-"*indent + "+ " + tm["ID"])


def traverseRootTM(tm, indent = 0, func = printIndentedID):
    func(tm, indent)
    tm.setdefault('children', [])

    for children in tm["children"]:
        traverseRootTM(children, indent+1, func)
    return 

def traverseAllRoots(TMS: dict, func = printIndentedID):
    for tm in TMS.items():
        traverseRootTM(tm[1], func=func)
    return

def assignParents( TMS ):

    for tmKey in TMS.keys(): #for every tm
        tm = TMS[tmKey]
        if "parent" in tm.keys(): #if they have a parent ref key and value
            childTM = tm
            parentKey = childTM.get("parent")
            if not parentKey in TMS:
                print("Error in parsing yaml data:"+ childTM[filename] +
                "references a parent key that is not found: " + parentKey) #TODO test
                exit -2
            parent = TMS[parentKey]  
            parent.setdefault('children', []).append(childTM)   
    
    for tmKey in list(TMS.keys()): #for every tm 
        tm = TMS[tmKey]
        if "parent" in tm.keys():
            TMS.pop(tmKey)
    return


def parseFiles(yamlFiles):
    TMS = {}
    for fileIn in yamlFiles:
        print ("processing:" + fileIn.name)
        if not fileIn.name.endswith('.yaml'):
            print("input file needs to be .yaml")
            exit -2   
        tmData = yaml.load(fileIn)#, Loader=SafeLoader)
        tmData["fileName"] = fileIn.name
        TMS[tmData["ID"]] = tmData
    assignParents(TMS)
    return TMS

def parseYamlThreatModelAndChildrenXXX(fileIn):  
    print ("processing:" + fileIn.name)
    fileIn.seek(0)
    if not fileIn.name.endswith('.yaml'):
        print("input file needs to be .yaml")
        exit -2   
    tmDict = yaml.load(fileIn)#, Loader=SafeLoader)
    # tmDict["fileName"] = fileIn.name
    # TMS[tmData["ID"]] = tmData

    if "children" in tmDict.keys():
        idList = tmDict['children']
        if idList == None:
            idList = []
        tmDict['children']=dict()
        for childrenIDDict in idList:
            childrenId = childrenIDDict['ID']
            childrenTMDict = parseYamlThreatModelAndChildrenXXX (  open( os.path.dirname(fileIn.name)  + os.path.sep +  childrenId +".yaml"))
            childrenTMDict['parent'] = tmDict
            tmDict['children'][childrenTMDict['ID']]=childrenTMDict

    return tmDict


def  lookupParent(tm):

    return 


# def createMarkdownReport(tmo, indent=0):



def createTitleAnchorHash(title):
    hash = title.lower().rstrip().replace(' ','-').replace(':','').replace(',','').replace("`","").replace("'","")
    return hash

SKIP_TOC = "skipTOC"

#Credits to https://github.com/exhesham/python-markdown-index-generator/blob/master/markdown_toc.py
def createTableOfContent(mdData):
    toc = ""
    lines = mdData.split('\n')
    for line in lines:
        if SKIP_TOC not in line:
            if re.match(r'^#+ ', line):
                title = re.sub('#','',line).strip()
                hash = createTitleAnchorHash(title)
                manipulated_line = '**[%s](#%s)**' % (title, hash)
                tabs = re.sub('#','  ',line.strip()[:line.strip().index(' ')+1])
                toc += (tabs+ '* ' + manipulated_line + "\n")
    return mdData.replace("__TOC_PLACEHOLDER__", toc)

def createRFIs(mdData):
    rfilist = []
    newstring = ''
    start = 0
    counter = 1
    
    for m in re.finditer(r"\(RFI[\s:]*(.*)\)", mdData):
        
        rfi = m.group(1) if m.group(1) else 'Please complete'
        rfilist.append(rfi)
        end, newstart = m.span()
        newstring += mdData[start:end]
        
        # doesn't cope with markdown embedded in html
        # rep = f'[^{counter}] '
        rep = f'<sup><a id="backtorfi{counter}" href="#rfi{counter}">[RFI:{counter}]</a></sup> '

        newstring += rep
        start = newstart
        counter += 1
    newstring += mdData[start:]

    #rfi = '\n'.join( [ f'[^{i+1}]: {r}' for i,r in enumerate(rfilist) ] )

    rfil = '\n'.join( [ f'<li id="rfi{i+1}">{r} <a href="#backtorfi{i+1}">&#8617</a></li>' for i,r in enumerate(rfilist) ] )

    rfi = '<ol>'+rfil+'</ol>'

    return newstring.replace("__RFI_PLACEHOLDER__", rfi)

def makeMarkdownLinkedHeader(level, title, skipTOC = False):
    code=  "<a name='"+createTitleAnchorHash(title) + "'></a>\n" + level * "#" + " " + title.rstrip()
    if skipTOC:
        code += " <div class='" + SKIP_TOC + "'></div>"
    return "\n" + code + "\n"
    
def processMultipleTMIDs(TMIDs, outputDir, browserSync, rootTMYamlFile, template, ancestorData, baseFileName):

    print ("processRootTMYaml file: " + rootTMYamlFile.name)
    if not rootTMYamlFile.name.lower().endswith('.yaml'):
        raise ValueError("input file "+ rootTMYamlFile.name + "needs to be .yaml")
    
    # tmDict = parseYamlThreatModelAndChildren(rootTMYamlFile)

    tmoRoot = ThreatModel(rootTMYamlFile)
 

    for tmid in TMIDs:
        processSingleTMID(tmid, outputDir, browserSync, tmoRoot, template, ancestorData, baseFileName)


def processSingleTMID(TMID, outputDir, browserSync, tmoRoot, template, ancestorData, baseFileName):

    if baseFileName is None:
        baseFileName = TMID

    mdOutFileName = baseFileName + ".md"
    htmlOutFileName = baseFileName + ".html"

    rootID = TMID.split('.')[0]
    if tmoRoot._id == rootID:
        tmo = tmoRoot
    else:
        raise Exception('root id: '+ rootID +' not recognized, should be : '+tmoRoot._id)

        
    for idPathPart in TMID.split('.')[1:]:
        tmo = tmo.getChildrenTMbyID(idPathPart)
        

    try:
        mdTemplate = Template(
        filename=  os.path.join(os.path.dirname(__file__),
            'template/'+template+'.mako'),
            lookup=TemplateLookup(
                directories=['.', 
                             os.path.join(os.path.dirname(__file__),'/template/'), "/"]
                            , output_encoding='utf-8', preprocessor=[lambda x: x.replace("\r\n", "\n")]
            ))
        # ancestorData = True
        mdReport = mdTemplate.render(tmo=tmo, ancestorData=ancestorData)
    except:
        # print(mako_exceptions.text_error_template().render())
        traceback = RichTraceback()
        for (filename, lineno, function, line) in traceback.traceback:
            print("File %s, line %s, in %s" % (filename, lineno, function))
            print(line, "\n")
        print("%s: %s" % (str(traceback.error.__class__.__name__), traceback.error))
        return 
        # raise BaseException("Template rendering error")

    mdReport = createTableOfContent(mdReport)

    mdReport = createRFIs(mdReport)


    postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport)
    return

def postProcessTemplateFile(outputDir, browserSync, mdOutFileName, htmlOutFileName, mdReport):
    mermaidHtmlTags = mdReport.replace(#FIX mermaid diagrams for html
                "<!-- mermaid start. Do not delete this comment-->\n```mermaid", "<div class=mermaid>").replace("```\n<!-- mermaid end. comment needed to it covert to HTML-->","</div>")

    htmlReport = markdown.markdown(mermaidHtmlTags, extensions=['md_in_html'])
        
    baseHTML = """<!DOCTYPE html>
        <html>
        <head>
        <style>
        @media print {
            .pagebreak {
                clear: both;
                min-height: 1px;
                page-break-after: always;
            }
        }</style>
        <link rel="stylesheet" href="css/tm.css">
        </head>
        <body>%BODY%</body>
        </html>
        """
    htmlReport = baseHTML.replace("%BODY%", htmlReport)

    if browserSync:
        htmlReport=htmlReport.replace("</body>","""
            <script id="__bs_script__">//<![CDATA[
        document.write("<script async src='http://HOST:3000/browser-sync/browser-sync-client.js?v=2.27.10'><\/script>".replace("HOST", location.hostname));//]]></script>
    </body> """)
        
    mermaid_script = """
<script src="https://cdn.jsdelivr.net/npm/mermaid/dist/mermaid.min.js"></script>
<script>mermaid.initialize({startOnLoad:true});
</script>
"""
    htmlReport=htmlReport.replace("</body>",    mermaid_script + "</body>")    


    outMDPath = os.path.join(outputDir, mdOutFileName)
    print ("output MD file:" + outMDPath)

    outHTMLPath = os.path.join(outputDir, htmlOutFileName)
    print ("output HTML file:" + outHTMLPath)

    with open(outHTMLPath, 'w') as outFile:
        outFile.write(htmlReport)

    with open(outMDPath, 'w') as outFile:
        outFile.write(mdReport)


