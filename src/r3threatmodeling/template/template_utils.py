import re
import html
from markdown import Markdown
from io import StringIO
from ..threatmodel_data import *

#from r3threatmodeling.template_utils import BaseThreatModelObject

# globalMarkDown_attr_list_ext = True ## for MKDOCS metadata headers


class HeadingNumberer:
    """
    Singleton class to track heading numbers across document generation.
    Maintains a hierarchical counter for headings (e.g., 1, 1.1, 1.1.1).
    """
    _instance = None
    _enabled = True
    
    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(HeadingNumberer, cls).__new__(cls)
            cls._instance.reset()
        return cls._instance
    
    def reset(self):
        """Reset all counters to start fresh."""
        self.counters = [0] * 10  # Support up to 10 levels of nesting
        
    def get_number(self, level):
        """
        Get the current number for a given level and increment it.
        Also resets all deeper level counters.
        
        Args:
            level: The heading level (1 for h1, 2 for h2, etc.)
            
        Returns:
            str: The formatted number string (e.g., "1.2.3")
        """
        if not self._enabled:
            return ""
            
        # Adjust for 0-based indexing
        idx = level - 1
        
        if idx < 0 or idx >= len(self.counters):
            return ""
        
        # Increment current level
        self.counters[idx] += 1
        
        # Reset all deeper levels
        for i in range(idx + 1, len(self.counters)):
            self.counters[i] = 0
        
        # Build the number string (e.g., "1.2.3")
        number_parts = []
        for i in range(idx + 1):
            if self.counters[i] > 0:
                number_parts.append(str(self.counters[i]))
        
        return ".".join(number_parts)
    
    @classmethod
    def enable(cls):
        """Enable heading numbering."""
        cls._enabled = True
        
    @classmethod
    def disable(cls):
        """Disable heading numbering."""
        cls._enabled = False
        
    @classmethod
    def is_enabled(cls):
        """Check if heading numbering is enabled."""
        return cls._enabled


# Global instance
_heading_numberer = HeadingNumberer()

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
    if ctx:
        useMarkDown_attr_list_ext=ctx['useMarkDown_attr_list_ext']
    else:
        useMarkDown_attr_list_ext = False
    # useMarkDown_attr_list_ext = globalMarkDown_attr_list_ext
    
    if isinstance(tmObject, BaseThreatModelObject):
        ahref=createObjectAnchorHash(tmObject)
        title=title or tmObject.title
    else:
        ahref=createTitleAnchorHash(title)

    # Get heading number if enabled
    heading_number = _heading_numberer.get_number(level)
    if heading_number:
        numbered_title = f"{heading_number} -    {title}"
    else:
        numbered_title = title

    #
    # Create a 'clean' version of the title for the TOC
    # specify this title using the "data-toc-label" attribute 
    # (requires the attr_list markdown extension)
    #
    # i.e. <h2 data-toc-label='Alternate title for TOC'>Heading Title</h2>    
    #
    toc_title = CLEAN_RE.sub('', numbered_title).rstrip()

    # if not useMarkDownHeaders and not tmObject:
    #     code=  "<a name='"+ahref + "'></a>\n\n" + level * "#" + " " + numbered_title.rstrip()
    #     code += f" {{: data-toc-label=\"{toc_title}\"}}"
    # else:
        # code=  "<a name='"+ahref + "'></a>\n\n" + f"<H{level} id=\"{ahref}\" >" + numbered_title.rstrip() + f"</H{level}>"

    if useMarkDown_attr_list_ext: #RENAME TO useMKDOCSsyntax
        # code = f"<H{level} id=\"{ahref}\" data-toc-label=\"{toc_title}\">" + numbered_title.rstrip() + f"</H{level}>"
        code = level * "#" + " " + numbered_title.rstrip() + f" {{: data-toc-label=\"{toc_title}\" id=\"{ahref}\" }}"

    else:
        # Build the header without embedding backslashes inside f-string expressions
        skip_html = "  <div class='skipTOC'></div>" if skipTOC else ""
        header = "#" * level + " " + numbered_title.rstrip()
        code = "\n\n" + header + ((" " + skip_html) if skip_html else "") + " <a id='" + ahref + "'></a>\n"

    return "\n" + code + "\n"
    
def createObjectAnchorHash(tmObject):
    #return tmObject.id[tmObject.id.find('.')+1:] #exclude the first TMID. from the anchor
    return tmObject.anchor

TAG_RE = re.compile(r'<[^>]+>')
def createTitleAnchorHash(title):
    hash = title.lower().rstrip().replace(' ','-').replace(':','').replace(',','').replace("`","").replace("'","")
    hash = TAG_RE.sub('', hash)
    return hash

def trueorFalseMark(value: bool) -> str:
    """
    Returns an HTML checkmark or cross mark based on the boolean value.
    Equivalent to the trueorFalseMark Mako template function.
    """
    if value:
        return '<span style="color:green;">&#10004;</span>'
    else:
        return '&#10060;'


# Helper functions for heading numbering
def enable_heading_numbering():
    """Enable automatic heading numbering (1, 1.1, 1.1.1, etc.)"""
    HeadingNumberer.enable()
    
def disable_heading_numbering():
    """Disable automatic heading numbering"""
    HeadingNumberer.disable()
    
def reset_heading_numbers():
    """Reset heading counters to start from 1 again"""
    _heading_numberer.reset()
    
def is_heading_numbering_enabled():
    """Check if heading numbering is currently enabled"""
    return HeadingNumberer.is_enabled()