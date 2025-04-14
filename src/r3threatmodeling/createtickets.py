#!/usr/bin/env python3

import os
from pprint import pprint
import sys
import argparse
from getpass import getpass
import re
import urllib.parse
import webbrowser

from r3threatmodeling import *

#R3TM_URI = 'https://security.r3.com'

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
      
   def id_for_field_value(self, field, value):
      allfields = self._meta['projects'][0]['issuetypes'][0]['fields']

      if field in self.fieldmap:
          allowed  = allfields[self.fieldmap['Severity']]['allowedValues']
          v = next(v for v in allowed if v['value'] == value)
          return v['id']

#
# Subclass the standard dict class to convert text keys to field ids
# We use dict because we want to prevent conversion for dict initialization
# in case there are mappings that we dont' want to do
#
class JiraFields(dict):
    def __init__(self, initwith=None, fieldmap=None, **kwargs):
        self.fieldmap = fieldmap
        super().__init__(initwith)

    def __setitem__(self, key, value):        
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

   
def review_jira_for_threat(jira, dest, issue_type, threat, tm_home):
   

   project = JiraProjectIssueType(jira, dest, issue_type)     
   
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

def getargs():
  parser = argparse.ArgumentParser(description = 'Create JIRA tickets for Threat Model')

  print(os.environ.get('R3TM_HOME'))

  parser.add_argument("--rootTMYaml",  default = None, required=True, type=open)
  parser.add_argument("--YAMLprefix",  default = "",required=False)
  parser.add_argument("--dryRun",     action='store_true',required=False)
  parser.add_argument("--all",        action='store_true',required=False)
  
  parser.add_argument('--jira',      help='JIRA URI',      default = os.environ.get('ATLASSIAN_URI'))
  parser.add_argument('--username',  help='JIRA username', default = os.environ.get('ATLASSIAN_USERNAME'))
  parser.add_argument('--password',  help='JIRA token',    default = os.environ.get('ATLASSIAN_PASSWORD'))
  parser.add_argument('--dest',      help="Destination project key", required=True)
  parser.add_argument('--type',      help='Issue Type', default = "Security Bug", required=False)

  parser.add_argument('--tmUri',     help="Threat Model URI", default = os.environ.get('R3TM_HOME'))

  #parser.add_argument('--field',  help="Additional field(s) set", metavar="KEY=VALUE",required=False, type=str, nargs='+', action=KeyValue, default={})  

  #args = parser.parse_args(['--issue', 'SD-126', '--dest', 'ENT', '--field', 'Squad=bar'])
  args = parser.parse_args()

  if not args.jira:     
    print('Please specify --jira or ATLASSIAN_URI environment')
    sys.exit(0)

  if not args.username:
    print('Please specify --username or ATLASSIAN_USERNAME environment')
    sys.exit(0)

  if not args.password:
    print('Please specify --username or ATLASSIAN_USERNAME environment')
    sys.exit(0)

  return args

def main():

    args = getargs()
    jira = JIRA(args.jira, basic_auth=(args.username, args.password))
 
    tm = ThreatModel(args.rootTMYaml)

    print('-' * 80)

    unmitigatedNoOperational = tm.getThreatsByFullyMitigatedAndOperational(False, False)

    for  threat in unmitigatedNoOperational:
        if hasattr(threat, '_ticketLink'):
            ticket = threat.ticketLink
            ref = ticket.split('/')[-1]
        else:
            ticket = '--'
            ref = ''
        print(f'{threat.parent.title:32} : {ref:16} : {threat.title}')
        #print(threat)
        for cm in threat.countermeasures:
            x = '**' if cm.inPlace else '  '
            print(f'  {x}{cm.title}')
        threat.ticketLink = f"http://jira....?id={threat.id}"

        answer = input("\nOpen JIRA? [Y]es/[N]o:").upper()
        if answer == 'Y' or answer == 'YES':

          #create_jira_for_threat(jira, args.dest, args.issueType, threat)
          review_jira_for_threat(jira, args.dest, args.type, threat, args.tmUri)
          while True:
            i = input("\nSubmitted JIRA ticket? Continue to next threat? [Y]es/[N]o:").upper()
            if answer == 'Y' or answer == 'YES':
              break

        if not args.all:
           sys.exit(0)

    if(not args.dryRun):
        #tm.dumpRecursive(prefix=args.YAMLprefix)
        pass

if __name__ == "__main__":
    main()