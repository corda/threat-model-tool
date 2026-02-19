#!/usr/bin/env python3

import os
from pprint import pprint
import sys
import argparse
from getpass import getpass
import re
import urllib.parse
import webbrowser

from ruamel.yaml import YAML
from r3threatmodeling import *
from r3threatmodeling.normalizeYAML import normalizeandDumpYAML

from jira import JIRA

    
class JiraProjectIssueType:
   def __init__(self, jira, project_name, issue_type_name):
      self._jira = jira
      self._meta = jira.createmeta(projectKeys=project_name, expand="projects.issuetypes.fields", issuetypeNames=issue_type_name)
      
   @property 
   def meta(self):
      return self._meta
   
   @property
   def fieldmap(self):
      # return key:name mappings for the specified project's custom fields
      if self._meta and self._meta['projects']:
        allfields = self._meta['projects'][0]['issuetypes'][0]['fields']
        return {field['name']:field['key'] for field in allfields.values() }
      
   @property
   def fieldvaluemap(self):#, fieldname):
      """
      # return key:name mappings for the specified project's custom fields
      if self._meta and self._meta['projects']:
        for field, fieldvals in self._meta['projects'][0]['issuetypes'][0]['fields'].items():
          #fieldvals = self._meta['projects'][0]['issuetypes'][0]['fields'][field]
          schema = fieldvals['schema']
          if schema['type'] == 'option':
            return {field['value']:field['id'] for field in fieldvals['allowedValues'] }
          elif schema['type'] == 'array':
            pass
          #if fieldvals['sch']
          return {field['name']:field['key'] for field in allfields.values() }
      """
      # Return a dict mapping field name to a dict of allowed value->id pairs
      result = {}
      if self._meta and self._meta['projects']:
          fields = self._meta['projects'][0]['issuetypes'][0]['fields']
          for fieldvals in fields.values():
              schema = fieldvals.get('schema', {})
              if schema.get('type') == 'option' and 'allowedValues' in fieldvals:
                  name = fieldvals.get('name')
                  if name:
                      result[name] = {v['value']: v['id'] for v in fieldvals['allowedValues']}
              elif schema.get('type') == 'array' and 'allowedValues' in fieldvals:
                  name = fieldvals.get('name')
                  if name:
                      result[name] = {v['name'] if 'name' in v else v['value']: v['id'] for v in fieldvals['allowedValues']}
      return result
      
   def id_for_field_value(self, fieldname, value):
      allfields = self._meta['projects'][0]['issuetypes'][0]['fields']

      if fieldname in self.fieldmap:
          allowed  = allfields[self.fieldmap[fieldname]]['allowedValues']
          v = next(v for v in allowed if v['value'] == value)
          return v['id']

#
# Subclass the standard dict class to convert text keys to field ids
# We use dict because we want to prevent conversion for dict initialization
# in case there are mappings that we dont' want to do
#
class JiraFields(dict):
    def __init__(self, initwith=None, fieldmap=None, valuemap=None,**kwargs):
        self.fieldmap = fieldmap
        self.valuemap = valuemap
        super().__init__(initwith)

    def __setitem__(self, key, value):        
        
        # translate the value if it is a string
        if key in self.valuemap and value in self.valuemap[key]:
          value = self.valuemap[key][value]

        #value = {'value': value}

        # translate the key name
        if key in self.fieldmap:
            key = self.fieldmap[key]
            print(f'Copying: {key} ({str(value)})')
        else:
            print(f'Missing: {key} (not copied)')
        key = key.lower()

        super().__setitem__(key, value)


def panelMD(type=None):
    match type:
        case 'info':    return "{panel:bgColor=#deebff}"
        case 'warning': return "{panel:bgColor=#fefae6}"
        case 'error':   return "{panel:bgColor=#ffebe6}"
        case 'note':    return "{panel:bgColor=#eae6ff}" 
        case 'success': return "{panel:bgColor=#e3fcef}"
        case _:         return "{panel}"
       
def treatment_plan(threat, hashes=True, tm_home="https://example.com"):
   secobs  = "\n".join([f"** {so.shortText()}" for so in threat.impactedSecObjs])
   desc = f"h4. Required Actions\n\n" \
        f"# Update the design document for {threat.parent.title} to describe how the threat will be mitigated.\n"\
        f"Alternatively provide a statement as to why the threat is not applicable, or is an accepted risk.\n" \
        f"# Ensure that the design clearly references the threat title and ID.\n" \
        f"# Ensure that the following Security Objectives are referenced by the design:\n{secobs}\n" \
        f"# Update this ticket with the location of the changes.\n" \
        f"# Refer to the Security Issue Handling policy for more information.\n" 
   
   return desc



def threat_description(threat, hashes=True, tm_home="https://example.com"):

  #panelb  = panelMD"{panel:bgColor=#deebff}"
  #panele  = "{panel}"

  reftxt  = f'*{threat.id}*\n{threat.title}'
  refuri  = f'[{threat.id}|{tm_home}/{threat.uri}]\n{threat.title}'
  
  missing = [cm for cm in threat.countermeasures if cm.inPlace is False]
  mitgs   = "\n".join([f"# {cm.title}\n{cm.description.strip()}" for idx, cm in enumerate(missing)])
  
  secobs  = "\n".join([f"** {so.shortText()}" for so in threat.impactedSecObjs])

  desc = f"This issue represents a design issue in the {threat.parent.title} design. " \
        f"Please ensure that the design is updated to detail how the threat will be mitigated.\n" \
        f"h4. Threat Reference\n{panelMD('error')}{refuri}{panelMD()}\n\n" \
        f"h4. Threat Description\n{threat.attack}\n\n" \
        f"h4. Proposed Mitigation(s)\n" \
        f"The following countermeasures are potential solutions to mitigate the described threat:\n\n{mitgs}\n\n" \
        f"h4. Required Actions\n\n" \
        f"# Update the design document for {threat.parent.title} to describe how the threat will be mitigated.\n"\
        f"Alternatively provide a statement as to why the threat is not applicable, or is an accepted risk.\n" \
        f"# Ensure that the design clearly references the threat title and ID.\n" \
        f"# Ensure that the following Security Objectives are referenced by the design:\n{secobs}\n" \
        f"# Update this ticket with the location of the changes.\n" \
        f"# Refer to the Security Issue Handling policy for more information.\n" \
        f"\n\n"
        
  
  if hashes:
    return re.sub(r'h(\d)\.\s', lambda match: '#' * int(match.group(1)) + ' ', desc)
  else:
    return desc

def risk_description(threat, hashes=True, tm_home="https://example.com"):
  reftxt  = f'*{threat.id}*\n{threat.title}'
  refuri  = f'[{threat.id}|{tm_home}/{threat.uri}]\n({threat.title})'

  missing = [cm for cm in threat.countermeasures if cm.inPlace is False]
  mitgs   = "\n".join([f"# {cm.title}\n{cm.description.strip()}" for idx, cm in enumerate(missing)])

  desc = f"{threat.attack}\n\n" \
        f"\n" \
        f"{panelMD('error')}\n" \
        f"*Threat Model Reference*\n" \
        f"This risk represents a potential threat identified in the {threat.parent.title} threat model:\n\n" \
        f"{refuri}{panelMD()}\n\n" \
        f"*Proposed Mitigation(s)*\n" \
        f"The following mitigations are potential solutions address the described threat:\n\n{mitgs}\n\n" \
        f"*Required Actions*\n\n" \
        f"# Review the risk and update the risk Likelyhood and/or Impact\n"\
        f"# Consider the proposed mitigation and update the treatment plan if applicable.\n"\
        f"# Adjust the Target Date for Closure according to the Asset and Risk Methodology policy document. \n" \
        f"\n\n"  
   
  if hashes:
    return re.sub(r'h(\d)\.\s', lambda match: '#' * int(match.group(1)) + ' ', desc)
  else:
    return desc

def review_jira_for_threat(jira, dest, issue_type, threat, tm_home):
   

   project = JiraProjectIssueType(jira, dest, issue_type)     
   
   if not project or not project.meta or not project.meta['projects']:
      print(f"Unable to find project {dest} or issue type {issue_type}")
      sys.exit(1)

   fields = JiraFields({
      'pid':       project.meta['projects'][0]['id'],
      'issuetype': project.meta['projects'][0]['issuetypes'][0]['id'],
      'summary':   threat.title,
      'description': threat_description(threat, hashes=False, tm_home=tm_home),
      'labels':    'Design-Issue'
   }, fieldmap = project.fieldmap)

   cvss = threat.cvssObject
   fields['CVSS Score']  = cvss.getSmartScoreVal()
   fields['CVSS Vector'] = cvss.clean_vector()
   fields['Severity']    = project.id_for_field_value('Severity', cvss.getSmartScoreSeverity())

   #print(pprint(fields))
   encoded = urllib.parse.urlencode(fields, quote_via=urllib.parse.quote)
   
   cmd = f"https://r3-cev.atlassian.net/secure/CreateIssueDetails!init.jspa?{encoded}"
   res =  webbrowser.open_new_tab(cmd)
   #print(f"Result:{res}")
        
   print(cmd)

def compliance(threat, compliance_type, fieldvaluemap=None):
   
   if hasattr(threat, 'compliance'):
      for ct in threat.compliance:
         if compliance_type in ct:
            compliancelist = []
            for cr in ct[compliance_type]:
              val = cr['ref'].split()[0]
              if fieldvaluemap and val in fieldvaluemap:
                  val = fieldvaluemap[val]
              compliancelist.append(val)
      
      return compliancelist

def map_cvss_to_impact(severity):
    """
    Map CVSS severity to JIRA Impact field values.
    This is a simplified mapping; adjust as necessary for your JIRA configuration.
    """
    impact_map = {
        'Critical': '5 - Very High',
        'High':     '4 - High',
        'Medium':   '3 - Medium',
        'Low':      '2 - Low',
        'None':     '1 - Very Low'        
    }
    return impact_map.get(severity, 'None')

def risk_rating(severity, likelyhood):
    match severity:
        case 'Critical': return 5*likelyhood
        case 'High':     return 4*likelyhood
        case 'Medium':   return 3*likelyhood
        case 'Low':      return 2*likelyhood
        case 'None':     return 1*likelyhood
        case _:          return 1

def treatment_plan_date(risk_rating):
  from datetime import date
  from dateutil.relativedelta import relativedelta
  if risk_rating <= 5: return  date.today() + relativedelta(months=2)
  if risk_rating <= 10: return  date.today() + relativedelta(months=1)
  if risk_rating <= 16: return  date.today() + relativedelta(weeks=2)
  if risk_rating <= 25: return  date.today() + relativedelta(weeks=1)


def review_risk_for_threat(jira, dest, issue_type, threat, tm_home, extra_fields={}):
   
   project = JiraProjectIssueType(jira, dest, issue_type)     
   
   if not project or not project.meta or not project.meta['projects']:
      print(f"Unable to find project {dest} or issue type {issue_type}")
      sys.exit(1)

   fields = JiraFields({
      'pid':       project.meta['projects'][0]['id'],
      'issuetype': project.meta['projects'][0]['issuetypes'][0]['id'],
      'summary':   f"[R3TM] {threat.title}",
      'description': risk_description(threat, hashes=False, tm_home=tm_home),
      'labels':    'Design-Issue'
   }, fieldmap = project.fieldmap,
      valuemap = project.fieldvaluemap)

   # Risk-specific fields
   #cvss = threat.cvssObject
   #rr = risk_rating(cvss.getSmartScoreSeverity(), 3)  # Assuming likelihood is 3 - Possible
   rr = risk_rating(threat.getSmartScoreDesc(), 3)

   fields['Impact']    = map_cvss_to_impact(threat.getSmartScoreVal())
   fields['Impact Description'] = threat.impact_desc
   fields['Risk Type'] = 'Security Risk'
   fields['Target Date for Closure'] = treatment_plan_date(rr).strftime('%d/%b/%Y').lstrip('0')
   fields['Incident Reported By (if not the person raising the ticket)'] = 'R3 Threat Model'
   fields['Likelihood'] = '3 - Possible'
   #fields['Additional ISO 27001 Control(s) after Risk Treatment'] = compliance(threat, 'ISO27001', fieldvaluemap=project.fieldvaluemap)
   #fields['Team Responsible for Corrective Action'] = 'Security'

   

   for key, val in extra_fields.items():
      fields[key] = val
      print(f'Adding: {key} ({str(val)})')
    
   """
    #if extra_field in project.fieldmap:
        key=destmap[extra_field]
        val=extra_fields[extra_field]
        fields[key] = val
        print(f'Adding: {key} ({str(val)})')
    else:
        print(f'Unknown field: {extra_field}')
   """
   #print(pprint(fields))
   encoded = urllib.parse.urlencode(fields, quote_via=urllib.parse.quote)
   
   cmd = f"https://r3-cev.atlassian.net/secure/CreateIssueDetails!init.jspa?{encoded}"
   res =  webbrowser.open_new_tab(cmd)
   #print(f"Result:{res}")
        
   print(cmd)
   
def create_jira_for_threat(jira, dest, issue_type, threat):

  project = JiraProjectIssueType(jira, dest, issue_type)
  
  fields = JiraFields({
    'project': dest,
    'issuetype': {'name': issue_type},
    'summary':   threat.title,
    'description': threat_description(threat, hashes=True)
  }, fieldmap=project.fieldmap)

  cvss = threat.cvssObject
  fields['CVSS Score']  = cvss.getSmartScoreVal()
  fields['CVSS Vector'] = cvss.clean_vector()
  fields['Severity']    = cvss.getSmartScoreSeverity()

  issue = jira.create_issue(fields)
  addr = f"<base>/browse/{issue.key}"
  print(addr)
  print(fields)

class KeyValue(argparse.Action):
    # Constructor calling
    def __call__( self , parser, namespace, values, option_string = None):
        setattr(namespace, self.dest, dict())          
        for value in values:
            # split it into key and value
            key, value = value.split('=')
            # assign into dictionary
            getattr(namespace, self.dest)[key] = value

def getargs():
  parser = argparse.ArgumentParser(description = 'Create JIRA tickets for Threat Model')

  print(os.environ.get('R3TM_HOME'))

  parser.add_argument("--rootTMYaml",  default = None, required=True, type=open)
  parser.add_argument("--TMID",       default=None, required=False, type=str)
  #parser.add_argument("--YAMLprefix",  default = "",required=False)
  #parser.add_argument("--dryRun",     action='store_true',required=False)
  parser.add_argument("--all",        action='store_true',required=False)
  parser.add_argument("--list",        action='store_true',required=False)
  
  parser.add_argument('--jira',      help='JIRA URI',      default = os.environ.get('ATLASSIAN_URI'))
  parser.add_argument('--username',  help='JIRA username', default = os.environ.get('ATLASSIAN_USERNAME'))
  parser.add_argument('--password',  help='JIRA token',    default = os.environ.get('ATLASSIAN_PASSWORD'))
  parser.add_argument('--dest',      help="Destination project key", required=True)
  parser.add_argument('--type',      help='Issue Type', default = "Security Bug", required=False)

  parser.add_argument('--tmUri',     help="Threat Model URI", default = os.environ.get('R3TM_HOME'))

  parser.add_argument('--field',  help="Additional field(s) set", metavar="KEY=VALUE",required=False, type=str, nargs='+', action=KeyValue, default={})  

  #args = parser.parse_args(['--issue', 'SD-126', '--dest', 'ENT', '--field', 'Squad=bar'])
  args = parser.parse_args()

  if not args.jira:     
    print('Please specify --jira or ATLASSIAN_URI environment')
    sys.exit(0)

  if not args.username:
    print('Please specify --username or ATLASSIAN_USERNAME environment')
    sys.exit(0)

  if not args.password:
    print('Please specify --username or ATLASSIAN_PASSWORD environment')
    sys.exit(0)

  return args

def update_yaml_with_ref(jira, path, threatid, ticketid):

    yaml = YAML(typ='rt')
    yaml.preserve_quotes = True
    
    with open(path, "r", encoding="utf-8-sig") as f:
      y = yaml.load(f)

      ythreat = next(ythreat for ythreat in y['threats'] if ythreat['ID'] == threatid)
      if not ythreat:
          print(f"Unable to find threat {threatid} in {path}")
          return False

      ythreat['ticketLink'] = f"{jira}/issues/{ticketid}"
  
    # write it back out to the same file but without the BOM
    print("Updating: ", path)
    with open(path, "w", encoding="utf-8") as f:
      yaml.indent(mapping=2, sequence=4, offset=2)
      yaml.dump(y, stream=f)#sys.stdout)
      f.close()
      return True

def update_threat_with_ref(threat, ticketref):

    y = threat.threatModel.originDict

    # relocate the original YAML object from this parsed threat
    ythreat = next((ythreat for ythreat in y['threats'] if ythreat['ID'] == threat.ID), None)
    if not ythreat:
        print(f"Unable to find threat {threat.id} in {threat.parent.fileName}")
        return False

    ythreat['ticketLink'] = ticketref
  
    # write it back out to the same file but without the BOM
    normalizeandDumpYAML(threat.threatModel, recursive=False)
    """

    print("Updating: ", threat.parent.fileName)
    with open(threat.parent.fileName, "w", encoding="utf-8") as f:
      yaml.indent(mapping=2, sequence=4, offset=2)
      yaml.dump(y, stream=f)#sys.stdout)
      f.close()
      return True
    """

def main():

    args = getargs()

    tm = ThreatModel(args.rootTMYaml)

    unmitigatedNoOperational = tm.getThreatsByFullyMitigatedAndOperational(False, False)

    for idx, threat in enumerate(unmitigatedNoOperational):
      tm = threat.threatModel
      
      print('-' * 80)
      print(f"Threat [{idx+1}/{len(unmitigatedNoOperational)}] ({threat.id})")      

      if args.TMID and args.TMID != tm._id:        
        print(f"   (Skipping)")
        continue  

      if hasattr(threat, '_ticketLink') and threat._ticketLink:
        ticket = threat._ticketLink
        ref = ticket.split('/')[-1]

        if not args.list:
          print(f"   (Skipping)")
          continue  
      else:
        ref = '   not linked  '

      print(f'[{ref:^16}] : {threat.title}')
      
      #threat.ticketLink = f"http://jira....?id={threat.id}"

      if not args.list:
        jira = JIRA(args.jira, basic_auth=(args.username, args.password))

        answer = input("\nOpen JIRA? [Y/N]: ").upper()
        if answer == 'Y' or answer == 'YES':
          #review_jira_for_threat(jira, args.dest, args.type, threat, args.tmUri)
          review_risk_for_threat(jira, args.dest, args.type, threat, args.tmUri, extra_fields=args.field)

        key = input("Enter [JIRA KEY] to link ticket into threat model, or press [ENTER] to continue: ").upper().strip()
        if key:
          ref = f"{args.jira}/browse/{key}"
          update_threat_with_ref(threat, ticketref=ref)

if __name__ == "__main__":
    main()