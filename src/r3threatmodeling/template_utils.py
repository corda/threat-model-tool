import re
import html
from markdown import Markdown
from io import StringIO

SKIP_TOC = "skipTOC"

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

def valueOr(o, a, alt):
    if hasattr(o, a ):
        ret =  getattr(o, a)
        return ret
    else:
        return alt
    
def mermaid_escape(text):
    text = re.sub(r"\(RFI[\s:]*(.*)\)", "", text)
    return html.escape(markdown_to_text(text).replace("\"","#quot;")).replace("(", "&lpar;").replace(")", "&rpar;")


def getShortDescForMermaid(attack, strSize):
    # try:
        if len(attack) >= strSize:
            return mermaid_escape(attack)[:strSize]+ "[...]"
        else:
            return mermaid_escape(attack)

def markdown_to_text(text):
    return __md.convert(text)

def makeMarkdownLinkedHeader(level, title, skipTOC = False):
    code=  "<a name='"+createTitleAnchorHash(title) + "'></a>\n" + level * "#" + " " + title.rstrip()
    if skipTOC:
        code += " <div class='" + SKIP_TOC + "'></div>"
    return "\n" + code + "\n"
    

def createTitleAnchorHash(title):
    hash = title.lower().rstrip().replace(' ','-').replace(':','').replace(',','').replace("`","").replace("'","")
    return hash