# -*- coding: utf-8 -*-
try:
    from soup import BeautifulSoup
except ImportError:
    import BeautifulSoup

#### UNICODE #######################################################################################

def decode_utf8(string):
    """ Returns the given string as a unicode string (if possible).
    """
    if isinstance(string, str):
        for encoding in (("utf-8",), ("windows-1252",), ("utf-8", "ignore")):
            try:
                return string.decode(*encoding)
            except:
                pass
        return string
    return unicode(string)

def encode_utf8(string):
    """ Returns the given string as a Python byte string (if possible).
    """
    if isinstance(string, unicode):
        try:
            return string.encode("utf-8")
        except:
            return string
    return str(string)

u = decode_utf8
s = encode_utf8

# For clearer source code:
bytestring = s

#### DOCUMENT OBJECT MODEL #########################################################################
# Tree traversal of HTML (or XML) source code.
# The Document Object Model (DOM) is a cross-platform and language-independent convention
# for representing and interacting with objects in HTML, XHTML and XML documents.
# BeautifulSoup is wrapped in Document, Element and Text classes that resemble the Javascript DOM.
# BeautifulSoup can of course be used directly since it is imported here.
# http://www.crummy.com/software/BeautifulSoup/

SOUP = (
    BeautifulSoup.BeautifulSoup,
    BeautifulSoup.Tag,
    BeautifulSoup.NavigableString,
    BeautifulSoup.Comment
)

NODE, TEXT, COMMENT, ELEMENT, DOCUMENT = \
    "node", "text", "comment", "element", "document"

#--- NODE ------------------------------------------------------------------------------------------

class Node:
    #! Нужно добавить возможность извлекать детей/родителей по айди,классу,типу
    def __init__(self, html, type=NODE, **kwargs):
        """ The base class for Text, Comment and Element.
            All DOM nodes can be navigated in the same way (e.g. Node.parent, Node.children, ...)
        """
        self.type = type
        self._p = not isinstance(html, SOUP) and BeautifulSoup.BeautifulSoup(u(html), **kwargs) or html

    @property
    def _beautifulSoup(self):
        # If you must, access the BeautifulSoup object with Node._beautifulSoup.
        return self._p

    def __eq__(self, other):
        # Two Node objects containing the same BeautifulSoup object, are the same.
        return isinstance(other, Node) and hash(self._p) == hash(other._p)

    def _wrap(self, x):
        # Navigating to other nodes yields either Text, Element or None.
        if isinstance(x, BeautifulSoup.Comment):
            return Comment(x)
        if isinstance(x, BeautifulSoup.Declaration):
            return Text(x)
        if isinstance(x, BeautifulSoup.NavigableString):
            return Text(x)
        if isinstance(x, BeautifulSoup.Tag):
            return Element(x)
        return x

    @property
    def parent(self):
        return self._wrap(self._p.parent)

    @property
    def children(self):
        return hasattr(self._p, "contents") and [self._wrap(x) for x in self._p.contents] or []

    @property
    def source(self):
        return self.__unicode__()
    html=source

    def next_sibling(self, skipEmpty=True):
        o=self._p.nextSibling
        if skipEmpty:
            emptyPattern=('', ' ', '\r', '\n', '\r\n')
            while o in emptyPattern: o=o.nextSibling
        return self._wrap(o)
    next = nextSibling = next_sibling

    def previous_sibling(self, skipEmpty=True):
        o=self._p.previousSibling
        if skipEmpty:
            emptyPattern=('', ' ', '\r', '\n', '\r\n')
            while o in emptyPattern: o=o.previousSibling
        return self._wrap(o)
    prev = previous = previousSibling = prevSibling = previous_sibling

    def traverse(self, visit=lambda node: None):
        """ Executes the visit function on this node and each of its child nodes.
        """
        visit(self); [node.traverse(visit) for node in self.children]

    def __len__(self):
        return len(self.children)
    def __iter__(self):
        return iter(self.children)
    def __getitem__(self, index):
        return self.children[index]

    def __repr__(self):
        return "Node(type=%s)" % repr(self.type)
    def __str__(self):
        return bytestring(self.__unicode__())
    def __unicode__(self):
        return u(self._p)

#--- TEXT ------------------------------------------------------------------------------------------

class Text(Node):
    """ Text represents a chunk of text without formatting in a HTML document.
        For example: "the <b>cat</b>" is parsed to [Text("the"), Element("cat")].
    """
    def __init__(self, string):
        Node.__init__(self, string, type=TEXT)
    def __repr__(self):
        return "Text(%s)" % repr(self._p)

class Comment(Text):
    """ Comment represents a comment in the HTML source code.
        For example: "<!-- comment -->".
    """
    def __init__(self, string):
        Node.__init__(self, string, type=COMMENT)
    def __repr__(self):
        return "Comment(%s)" % repr(self._p)

#--- ELEMENT ---------------------------------------------------------------------------------------

class Element(Node):

    def __init__(self, html):
        """ Element represents an element or tag in the HTML source code.
            For example: "<b>hello</b>" is a "b"-Element containing a child Text("hello").
        """
        Node.__init__(self, html, type=ELEMENT)
        self.userData={}

    def __setitem__(self, key, value):
        self.userData[key]=value

    def __getitem__(self, key):
        return self.userData[key]

    @property
    def tagname(self):
        return self._p.name
    tag = tagName = tagname

    @property
    def attributes(self):
        return self._p._getAttrMap()
    attr = attributes

    @property
    def classes(self):
        return self.attributes["class"].split(' ') if 'class' in self.attributes else []

    @property
    def id(self):
        return self.attributes.get("id")

    def get_elements_by_tagname(self, v, limit=None):
        """ Returns a list of nested Elements with the given tag name.
            The tag name can include a class (e.g. div.header) or an id (e.g. div#content).
        """
        if isinstance(v, list):
            out=[]
            for vv in v:
                out=out+self.get_elements_by_tagname(vv)
            return out
        if isinstance(v, basestring): v=v.strip()
        if isinstance(v, basestring) and ',' in v:
            out=[]
            for vv in v.split(','):
                out=out+self.get_elements_by_tagname(vv)
            return out
        if isinstance(v, basestring) and "#" in v:
            v1, v2 = v.split("#")
            v1 = v1 in ("*","") or v1.lower()
            return [Element(x) for x in self._p.findAll(v1, id=v2)]
        if isinstance(v, basestring) and "." in v:
            v1, v2 = v.split(".")
            v1 = v1 in ("*","") or v1.lower()
            return [Element(x) for x in self._p.findAll(v1, v2)]
        return [Element(x) for x in self._p.findAll(v in ("*","") or v.lower())]
    byTag = by_tag = getElementsByTagname = get_elements_by_tagname
    get = get_elements_by_tagname

    def get_first_by_tagname(self, v):
        s=self.get_elements_by_tagname(v, limit=1)
        if not len(s): return None
        return s[0]
    getOne = getFirst = get_first_by_tagname

    def get_element_by_id(self, v):
        """ Returns the first nested Element with the given id attribute value.
        """
        return ([Element(x) for x in self._p.findAll(id=v, limit=1) or []]+[None])[0]
    byId = by_id = getElementById = get_element_by_id

    def get_elements_by_classname(self, v):
        """ Returns a list of nested Elements with the given class attribute value.
        """
        return [Element(x) for x in (self._p.findAll(True, v))]
    byClass = by_class = getElementsByClassname = get_elements_by_classname

    def get_elements_by_attribute(self, **kwargs):
        """ Returns a list of nested Elements with the given attribute value.
        """
        return [Element(x) for x in (self._p.findAll(True, attrs=kwargs))]
    byAttribute = byAttr = by_attribute = by_attr = getElementsByAttribute = get_elements_by_attribute

    @property
    def content(self):
        """ Yields the element content as a unicode string.
        """
        return u"".join([u(x) for x in self._p.contents])

    @property
    def source(self):
        """ Yields the HTML source as a unicode string (tag + content).
        """
        return u(self._p)
    html = source

    def get_elements_by_soup(self, *args, **kwargs):
        """ Returns a list of nested Elements via ._beautifulSoup.findAll
        """
        return [Element(x) for x in (self._p.findAll(*args, **kwargs))]
    bySoup=get_elements_by_soup

    def __repr__(self):
        return "Element(tag='%s')" % bytestring(self.tagname)

#--- DOCUMENT --------------------------------------------------------------------------------------

class Document(Element):

    def __init__(self, html, **kwargs):
        """ Document is the top-level element in the Document Object Model.
            It contains nested Element, Text and Comment nodes.
        """
        # Aliases for BeautifulSoup optional parameters:
        kwargs["selfClosingTags"] = kwargs.pop("self_closing", kwargs.get("selfClosingTags"))
        Node.__init__(self, u(html).strip(), type=DOCUMENT, **kwargs)

    @property
    def declaration(self):
        """ Yields the <!doctype> declaration, as a TEXT Node or None.
        """
        for child in self.children:
            if isinstance(child._p, BeautifulSoup.Declaration):
                return child

    @property
    def head(self):
        return self._wrap(self._p.head)
    @property
    def body(self):
        return self._wrap(self._p.body)
    @property
    def tagname(self):
        return None
    tag = tagname

    def __repr__(self):
        return "Document()"

DOM = Document

#article = Wikipedia().search("Document Object Model")
#dom = DOM(article.html)
#print dom.get_element_by_id("References").source
#print [element.attributes["href"] for element in dom.get_elements_by_tagname("a")]
#print dom.get_elements_by_tagname("p")[0].next.previous.children[0].parent.__class__
#print


if(__name__=='__main__'):
    print 'ok'
    raw_input()