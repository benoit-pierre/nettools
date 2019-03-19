
'''
nettools - Copyright 2018-2019 python nettools team, see AUTHORS.md

This software is provided 'as-is', without any express or implied
warranty. In no event will the authors be held liable for any damages
arising from the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it
freely, subject to the following restrictions:

1. The origin of this software must not be misrepresented; you must not
   claim that you wrote the original software. If you use this software
   in a product, an acknowledgment in the product documentation would be
   appreciated but is not required.
2. Altered source versions must be plainly marked as such, and must not be
   misrepresented as being the original software.
3. This notice may not be removed or altered from any source distribution.
'''

import copy
from html.parser import unescape as python_html_unescape
import re

from nettools.texthelpers import is_punctuation, is_whitespace


def unescape(t):
    return python_html_unescape(t)


cpdef str html_escape(t):
    import html
    return html.escape(t).replace("\u00A0", "&nbsp;")


class TextNode:
    def __init__(self, text):
        self.content = text
        self.node_type = "text"
        self.children = []

    def serialize(self, prettify=False, indent=False):
        indent_prefix = ""
        if prettify:
            indent_prefix = " " * (indent * 4)
        return indent_prefix + self.content.replace("&", "&amp;").\
            replace("<", "&lt;").replace(">", "&gt;")

    def __repr__(self):
        inner = self.content
        if len(inner) > 200:
            inner = inner[:100] + "..." + inner[-90:]
        return "'" + inner.replace("'", "'\"'\"'") + "'"


class HTMLElement(object):
    def __init__(self, html, attributes):
        self.content = html
        self.node_type = "element"
        self.is_self_closing = False
        self.name = ""
        self.children = []
        self.attributes = dict()
        self.attributes_as_list = attributes
        for (aname, avalue) in attributes:
            self.attributes[aname] = avalue

    def get_attribute(self, key):
        try:
            return self.attributes[key]
        except KeyError as e:
            for k in self.attributes:
                if k.lower() == key.lower():
                    return self.attributes[k]
            return None

    def add_attribute(self, key, value=None):
        self.attributes_as_list.append((key, value))
        self.attributes[key] = value

    def serialize_head(self):
        t = "<" + self.name
        for a in [entry[0] for entry in self.attributes_as_list]:
            if self.attributes[a] is None:
                t += " " + a
                continue
            t += " " + a + "=\""
            t += self.attributes[a].replace("&", "&amp;").\
                replace("\n", "&#10;").\
                replace("\r", "&#13;").\
                replace("\t", "&#9;").\
                replace("\0", "&#0;").\
                replace("\"", "&quot;") + "\""
        if self.is_self_closing:
            t += "/"
        return t + ">"

    def serialize_children(self, prettify=False, indent=0):
        t = ""
        for child in self.children:
            t += child.serialize(prettify=prettify,
                indent=indent)
            if prettify:
                t += "\n"
        return t

    def serialize(self, prettify=False, indent=0):
        indent_prefix = ""
        if prettify:
            indent_prefix = " " * (indent * 4)
        if self.is_self_closing:
            return indent_prefix +\
                self.serialize_head()
        t = indent_prefix + self.serialize_head()
        if prettify:
            t += "\n" 
        t += self.serialize_children(prettify=prettify,
                indent=(indent+1))
        t += indent_prefix + "</" + self.name + ">"
        return t

    def __repr__(self):
        inner = self.serialize(prettify=False)
        if len(inner) > 200:
            inner = inner[:100] + "..." + inner[-90:]
        return "'" + inner.replace("'", "'\"'\"'") + "'"

def parse_tag(html):
    is_self_closing = False
    is_closing = False
    in_quote_type = None
    in_quote_started_at = None
    tag_name = ""
    in_tag_name = False
    seen_tag_name = False

    attributes = []
    seen_nonwhitespace_attr_value = False
    current_attr_name = ""
    current_attr_value = None
    in_attribute_value = False

    def finish_attribute():
        nonlocal current_attr_name, current_attr_value
        if len(current_attr_name) > 0:
            attributes.append((current_attr_name,
                current_attr_value))
        current_attr_name = ""
        current_attr_value = None

    def regfind(s, p):
        result = re.search(p, s, re.MULTILINE)
        if result != None:
            return result.start()
        return -1

    i = -1
    while (i < len(html) - 1):
        i += 1
        c = html[i]

        if not seen_tag_name and not in_tag_name and \
                (c not in [
                " ", "\r", "\n", "\t", "<", "/", "\\"]):
            seen_tag_name = True
            in_tag_name = True
            if c == "'" or c == "\"" or c == ">" or \
                    c == "=":
                in_tag_name = False
                tag_name = ""
        if in_tag_name:
            if c in [" ", "\r", "\n", "\t", "<", ">",
                    "/", "&", "\"", "'", "\\", "="]:
                in_tag_name = False
                if c == "=":
                    # This is an attribute.
                    current_attr_name = tag_name
                    tag_name = ""
            else:
                # Scan to end of tag name:
                end_of_name = regfind(html[i:],
                    "[ /\\\\\\r\\n\\t=\"'><]")
                if end_of_name < 0:
                    tag_name += html[i:]
                    i += len(html[i:])
                    in_tag_name = False
                    break
                else:
                    tag_name += html[i:end_of_name + i]
                    i += end_of_name - 1
                    in_tag_name = False
                    continue

        if in_quote_type == None:
            if c == "/":
                if not seen_tag_name:
                    is_closing = True
                else:
                    is_self_closing = True
            if c == "\"" or c == "'":
                in_quote_started_at = i
                in_quote_type = html[i]
                continue
            if c == ">":
                break

            # End attribute values at whitespace:
            if c in [" ", "\r", "\t"] and in_attribute_value and \
                    seen_nonwhitespace_attr_value:
                in_attribute_value = False

            # Handle new attribute or unquoted attribute value:
            if not c in [" ", "\r", "\n", "\t", "=",
                    "\"", "'", ">", "<", "/", "\\"]:
                if not in_attribute_value:
                    finish_attribute()
                else:
                    seen_nonwhitespace_attr_value = True

                # Find end of attribute name or value:
                end_of_name = regfind(html[i:],
                    "[ \\r\\n\\t=\"'><\\/\\\\]")
                if end_of_name < 0:
                    i += end_of_name
                    break
                val = html[i:i + end_of_name]
                if end_of_name > 0:
                    i += end_of_name - 1

                if in_attribute_value:
                    current_attr_value += val
                    in_attribute_value = False
                else:
                    current_attr_name = val

            if c == "=":
                if current_attr_value is None:
                    current_attr_value = ""
                    in_attribute_value = True
                    seen_nonwhitespace_attr_value = False
                else:
                    # Spurious '='. End previous attribute.
                    finish_attribute()
        else:
            seen_nonwhitespace_attr_value = True
            if c == in_quote_type:
                quoted_str = html[in_quote_started_at:i + 1]
                in_quote_started_at = None
                in_quote_type = None
                if in_attribute_value:
                    current_attr_value += unescape(
                        quoted_str[1:-1])
    finish_attribute()

    return (i + 1, tag_name, attributes,
        is_closing, is_self_closing)

def parse_xml(xml):
    return parse(xml, void_tags=[])

def parse(html, void_tags=None):
    try:
        html = html.decode("utf-8", "replace")
    except AttributeError:
        pass
    return parse_recurse(html, void_tags=void_tags)[1]

def parse_recurse(html, void_tags=None, stop_at_closing=False):
    if void_tags is None:
        void_tags = [
            "area", "base", "br", "col",
            "command", "embed", "hr", "img",
            "input", "keygen", "link", "meta",
            "param", "source", "track", "wbr",
        ]

    parsed_chars = 0
    result = []

    while True:
        # Parse text in front of next tag:
        next_tag = html.find("<")
        if next_tag < 0:
            parsed_chars += len(html)
            if len(html) > 0:
                result.append(TextNode(unescape(html)))
            break
        if next_tag > 0:
            result.append(TextNode(unescape(html[:next_tag])))
        html = html[next_tag:]
        parsed_chars += next_tag

        # Opening tag of next element:
        (tag_length, tag_name, attributes,
            is_closing_tag, is_self_closing_tag) =\
            parse_tag(html)
        if is_closing_tag and stop_at_closing:
            # We should forget about this and exit here, since this
            # item belongs to our parent parse() and not us.
            break
        opening_tag = html[:tag_length]
        html = html[tag_length:]
        parsed_chars += tag_length
        element = HTMLElement(opening_tag, attributes)
        element.name = tag_name

        # If this is self-closing, don't parse contents + closing tag:
        if is_self_closing_tag or is_closing_tag or \
                tag_name in void_tags:
            if is_self_closing_tag or tag_name in void_tags:
                element.is_self_closing = True
            result.append(element)
            continue

        # Parse element contents:
        (content_length, content_children) = parse_recurse(html,
            void_tags=void_tags, stop_at_closing=True)
        html = html[content_length:]
        parsed_chars += content_length
        element.children = content_children

        # Parse closing tag:
        (tag_length, tag_name, attributes,
            is_closing_tag, is_self_closing_tag) =\
            parse_tag(html)
        if tag_name != element.name or \
                not is_closing_tag or is_self_closing_tag:
            # Not the closing tag. Re-parse as new element:
            result.append(element)
            continue
        parsed_chars += tag_length
        html = html[tag_length:]

        # Add element to result:
        result.append(element)

        continue

    return (parsed_chars, result)

def linkify_html(html_text, linkify_with_blank_target=True):
    extracted_doctype = ""
    if html_text.lstrip().lower().startswith("<!doctype "):
        start_of_doctype = html_text.lower().find("<!doctype ")
        if start_of_doctype >= 0:
            end_of_doctype = html_text[start_of_doctype:].find(">")
            if end_of_doctype >= 0:
                extracted_doctype = html_text[:(start_of_doctype +
                    end_of_doctype + 1)]
                html_text = html_text[len(extracted_doctype):]
    parsed_html = parse(html_text)
    def linkified_elements(els):
        def len_if_url(text):
            if text.find(".") < 0:
                return None
            if len(text.lstrip()) != len(text):
                return None
            k = 0
            confirmed_url = False
            bracket_nesting = None
            had_dot = False
            while k < len(text):
                if text[k:].startswith("://"):
                    if had_dot:
                        return None
                    confirmed_url = True
                    k += len("://")
                    continue
                elif text[k] != "%" and \
                        is_punctuation(text[k]) and \
                        text[k] != "." and text[k] != "/" and \
                        text[k] != "-":
                    if not had_dot:
                        return None
                    if text[k] == "(" or text[k] == "[":
                        if bracket_nesting != None or \
                                not confirmed_url:
                            return None
                        bracket_nesting = ")"
                        if text[k] == "[":
                            bracket_nesting = "]"
                        k += 1
                        continue
                    else:
                        if bracket_nesting == text[k]:
                            bracket_nesting = None
                            k += 1
                            continue
                        elif confirmed_url:
                            return k
                        else:
                            return None
                elif is_whitespace(text[k]):
                    if not confirmed_url:
                        return None
                    if bracket_nesting != None and \
                            text[k] == " " and \
                            not is_punctuation(text[k - 1]):
                        k += 1
                        continue
                    if bracket_nesting != None:
                        if k > 0 and is_punctuation(text[k - 1]):
                            k -= 1
                    return k
                elif text[k] == "." and bracket_nesting is None:
                    if k == 0 or k == len(text) - 1 or \
                            is_whitespace(text[k + 1]) or \
                            is_punctuation(text[k + 1]):
                        if confirmed_url:
                            return k
                        return None
                    had_dot = True
                    common_endings = ["com", "net", "org",
                        "de", "cn", "co.uk", "uk",
                        "info", "eu", "ru"]
                    for common_ending in common_endings:
                        if text[k + 1:].startswith(common_ending):
                            if len(text) == k + 1 + len(common_ending):
                                return len(text)
                            c = text[k + 1 + len(common_ending)]
                            if is_whitespace(c) or \
                                    is_punctuation(c) or \
                                    c == "/":
                                if c != "/":
                                    return (k + 1 + len(common_ending))
                                confirmed_url = True
                                break
                elif text[k] == "/":
                    if not had_dot:
                        return None
                    confirmed_url = True
                k += 1
            if not confirmed_url:
                return None
            return k

        result = []
        for el in els:
            new_el = copy.copy(el)
            if new_el.node_type == "element":
                new_el.children = linkified_elements(new_el.children)
            elif new_el.node_type == "text":
                if new_el.content.find("www.") < 0 and \
                        new_el.content.find("/") < 0:
                    result.append(new_el)
                    continue
                def clean_link(link):
                    if link.find("://") < 0:
                        return ("https://" + link)
                    return link
                blank_addition = " target='_blank' rel=noopener"
                if not linkify_with_blank_target:
                    blank_addition = ""
                last_link_end = 0
                i = 0
                while i < len(new_el.content):
                    url_len = len_if_url(new_el.content[i:])
                    if url_len != None:
                        if i > 0:
                            text_el = TextNode(new_el.content[:i])
                            result.append(text_el)
                        result.append(parse("<a href='" +
                            html_escape(clean_link(
                            new_el.content[i:i + url_len])).
                            replace("'", "&apos;") +
                            "'" + blank_addition + ">" + html_escape(
                            new_el.content[i:i + url_len]) +
                            "</a>")[0])
                        i += url_len
                        last_link_end = i
                        continue
                    i += 1
                if i > last_link_end:
                    text_el = TextNode(new_el.content[last_link_end:])
                    result.append(text_el)
                continue
            else:
                raise RuntimeError("unexpected node type: " +
                    str(new_el.node_type))
            result.append(new_el)
        return result
    parsed_html = linkified_elements(parsed_html)
    result = ""
    for parsed_el in parsed_html:
        result += parsed_el.serialize()
    return extracted_doctype + result

def depth_first_walker(html, callback, visit_out_callback=None):
    result = parse(html)
    if len(result) == 0:
        return None
    nestings = [(result, 0)]
    current_element = result[0]
    while True:
        result = callback(current_element)
        if result is False:
            return current_element
        if len(current_element.children) > 0:
            # Since this is depth first, descend into children immediately:
            nestings.append((current_element.children, 0))
            current_element = nestings[-1][0][nestings[-1][1]]
            continue
        else:
            # Has no child. Therefore, do visit out immediately:
            if visit_out_callback != None:
                result = visit_out_callback(current_element)
                if result is False:
                    return current_element
            # Check if there is no sibling left:
            if len(nestings[-1][0]) <= nestings[-1][1] + 1:
                # No sibling left. Ascend up, and call visit out on
                # parent of which we've now visited all children:
                nestings = nestings[:-1]
                if visit_out_callback != None and len(nestings) > 0:
                    result = visit_out_callback(nestings[-1][0]\
                        [nestings[-1][1]])
                    if result is False:
                        return nestings[-1][0][nestings[-1][1]]
                # While we continue to have no siblings left on the path
                # upwards, continue to call visit out and ascend:
                while len(nestings) > 0 and \
                        not len(nestings[-1][0]) > nestings[-1][1] + 1:
                    nestings = nestings[:-1]
                    if visit_out_callback != None and len(nestings) > 0:
                        result = visit_out_callback(nestings[-1][0]\
                            [nestings[-1][1]])
                        if result is False:
                            return nestings[-1][0][nestings[-1][1]]
                # If no layers are left, stop:
                if len(nestings) == 0:
                    current_element = None
                    break
            # Arriving here, there must be a sibling left. Continue there:
            nestings[-1] = [nestings[-1][0], nestings[-1][1] + 1]
            current_element = nestings[-1][0][nestings[-1][1]]
            continue
    if current_element != None:
        return current_element
    return None

