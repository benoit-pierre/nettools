
'''
nettools - Copyright 2018 python nettools team, see AUTHORS.md

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
sys.path = [os.path.abspath(os.path.dirname(__file__))] + sys.path

import nettools.htmlparse as htmlparse

def test_parser():
    result = htmlparse.parse("<a>&lt;3</a>")
    result_html = str(result)
    assert(result[0].serialize() == "<a>&lt;3</a>")

