import re
import html
from markdown import Markdown
from io import StringIO
from .threatmodel_data import *

#from r3threatmodeling.template_utils import BaseThreatModelObject

# globalMarkDown_attr_list_ext = True ## for MKDOCS metadata headers

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


def unmark(text):
    return html.escape(__md.convert(text))



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
    text = html.escape(markdown_to_text(text).replace("\"","'").replace(";","&semi;").replace("(", "&lpar;").replace(")", "&rpar;"))
    return text


def getShortDescForMermaid(attack, strSize):
    # try:
        if len(attack) >= strSize:
            return mermaid_escape(attack)[:strSize]+ "[...]"
        else:
            return mermaid_escape(attack)

def markdown_to_text(text):
    return __md.convert(text)


def renderNestedMarkdownList(data, level=0, stream=None, firstIndent=None):
    """
    Recursively renders nested dictionaries and lists into a Markdown list string.
    """
    initial_call = stream is None
    if initial_call:
        stream = StringIO()

    indent = "  " * level

    if isinstance(data, dict):
        for key, value in data.items():
            if not stream.getvalue() and firstIndent:
                # For the first level, we don't add a hyphen
                stream.write(f"{firstIndent}{key}: ")
            else:
                stream.write(f"{indent}- **{key}**: ")
            if isinstance(value, (dict, list)):
                stream.write("\n")  # Add newline before nested list/dict
                renderNestedMarkdownList(value, level + 1, stream, firstIndent=firstIndent) # Pass stream recursively
            else:
                stream.write(f"{value}\n") # Add newline after simple value
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                # For dictionaries within a list, start with a hyphen on the current level
                # stream.write(f"{indent}- \n")
                # Then render the dictionary content indented further
                renderNestedMarkdownList(item, level + 1, stream, firstIndent=firstIndent) # Pass stream recursively
            elif isinstance(item, list):
                 # Handle nested lists
                stream.write(f"{indent}- \n")
                renderNestedMarkdownList(item, level + 1, stream, firstIndent=firstIndent) # Pass stream recursively
            else:
                stream.write(f"{indent}- {item}\n")

    if initial_call:
        return stream.getvalue()
    # For recursive calls, we don't return anything, just write to the stream


#
# useMarkDownHeaders = True will hide the header from MKDocs TOC
# skipTOC    = unsure if this has any effect!
# tmObject   = threat model object to use as basis for ID
#
CLEAN_RE = re.compile(r'[\<\>\)\(]+.*$')

def makeMarkdownLinkedHeader(level, title, ctx, skipTOC = False, tmObject = None):
    useMarkDown_attr_list_ext=ctx['useMarkDown_attr_list_ext']
    # useMarkDown_attr_list_ext = globalMarkDown_attr_list_ext
    
    if isinstance(tmObject, BaseThreatModelObject):
        ahref=createObjectAnchorHash(tmObject)
        title=title or tmObject.title
    else:
        ahref=createTitleAnchorHash(title)

    #
    # Create a 'clean' version of the title for the TOC
    # specify this title using the "data-toc-label" attribute 
    # (requires the attr_list markdown extension)
    #
    # i.e. <h2 data-toc-label='Alternate title for TOC'>Heading Title</h2>    
    #
    toc_title = CLEAN_RE.sub('', title).rstrip()

    # if not useMarkDownHeaders and not tmObject:
    #     code=  "<a name='"+ahref + "'></a>\n\n" + level * "#" + " " + title.rstrip()
    #     code += f" {{: data-toc-label=\"{toc_title}\"}}"
    # else:
        # code=  "<a name='"+ahref + "'></a>\n\n" + f"<H{level} id=\"{ahref}\" >" + title.rstrip() + f"</H{level}>"

    if useMarkDown_attr_list_ext: #RENAME TO useMKDOCSsyntax
        # code = f"<H{level} id=\"{ahref}\" data-toc-label=\"{toc_title}\">" + title.rstrip() + f"</H{level}>"
        code = level * "#" + " " + title.rstrip() + f" {{: data-toc-label=\"{toc_title}\" id=\"{ahref}\" }}"

    else:
        code = f"""
<a name='{ahref}'></a>
{'#' * level} {title.rstrip()}
"""
        
        if skipTOC:
            code += " <div class='" + SKIP_TOC + "'></div>"

    return "\n" + code + "\n"
    
def createObjectAnchorHash(tmObject):
    #return tmObject.id[tmObject.id.find('.')+1:] #exclude the first TMID. from the anchor
    return tmObject.anchor

TAG_RE = re.compile(r'<[^>]+>')
def createTitleAnchorHash(title):
    hash = title.lower().rstrip().replace(' ','-').replace(':','').replace(',','').replace("`","").replace("'","")
    hash = TAG_RE.sub('', hash)
    return hash