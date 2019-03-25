
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


from nettools.htmlparse import parse as html_parse
from nettools.htmlparse import remove_html_comments
from nettools.nettools_version import VERSION


cdef class DocumentParagraphInlineText:
    cdef public dict css_attributes
    cdef public str text


cdef class DocumentParagraph:
    cdef public object paragraph_elements


def parse_from_string(htmldoc,
                      allow_access_same_folder_files=False,
                      allow_access_remote_files=True,
                      remote_fetch_user_agent="python-nettools/" + VERSION
                     ):
    try:
        htmldoc = htmldoc.decode("utf-8", "replace")
    except AttributeError:
        pass
    htmldoc = remove_html_comments(htmldoc)
    if htmldoc.lstrip().lower().find("<!doctype "):
        htmldoc = htmldoc.lstrip()[1:].partition(">")[2]
    elements = html_parse(htmldoc)
    for el in elements:
        pass
