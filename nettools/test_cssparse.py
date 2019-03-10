
'''
nettools - Copyright 2019 python nettools team, see AUTHORS.md

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

import os
import sys
sys.path = [os.path.abspath(os.path.join(
                            os.path.dirname(__file__), ".."))] + sys.path

import nettools.cssparse as cssparse

def test_extract_string_without_comments():
    result = cssparse.extract_string_without_comments(
        "abc /*def*/ flu {value:'/*test'}"
    )
    assert(result == "abc  flu {value:'/*test'}")
    result = cssparse.extract_string_without_comments(
        "/* \"abc \" def\\\" */\"ab\\\"/*\""
    )
    assert(result == "\"ab\\\"/*\"")


def test_extract_rule_strings():
    result = cssparse.extract_rule_strings(
        "myrule{a:1}/*test } a */myrule2{b:2}"
    )
    assert(len(result) == 2)
    assert(result[0] == "myrule{a:1}")
    assert(result[1] == "myrule2{b:2}")


def test_parse():
    result = cssparse.parse("""
        * {padding:5px}
        body {height:15px; padding:10px;}
    """)

    assert(len(result.rules) == 2)
    assert(result.rules[0].selector.items == ["*"])
    assert(len(result.rules[0].attributes) == 1)
    assert(result.rules[1].selector.items == ["body"])
    assert(len(result.rules[1].attributes) == 2)


def test_complex_selector_scenarios():
    result = cssparse.parse("""
        * {padding:5px}
        body {height:15px; padding:10px;}
    """)
    attributes = result.get_item_attributes("body")
    assert(set(attributes.keys()) == {"height", "padding"})
    assert(attributes["height"].value == "15px")

    result = cssparse.parse("""
        body {height:15px; padding:10px;}
        * {padding:5px}
    """)
    attributes = result.get_item_attributes("body")
    assert(set(attributes.keys()) == {"height", "padding"})
    assert(attributes["height"].value == "15px")

    result = cssparse.parse("""
        body {height:15px; padding:10px;}
        body {padding:5px}
    """)
    attributes = result.get_item_attributes("body")
    assert(set(attributes.keys()) == {"height", "padding"})
    assert(attributes["height"].value == "5px")
