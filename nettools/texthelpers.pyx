
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
import re


cdef frozenset punctuation_set = frozenset({
    ",", ".", "!", "?", ";", ":",
    "-", "–", #endash,
    "—", #emdash,
    "‘", "’", "”", "“", "\"", "'",
    "(", ")", "[", "]", "~",
    "*", "#", "%", "^", "=",
    "{", "}", "+", "$", "&",
    "<", ">", "/", "\\", "@"
})


cpdef object is_punctuation(str c):
    """ Returns True if certain it is punctuation,
        False if certain it is NOT punctuation,
        None if uncertain.

        (unicode makes things complicated, so we're decidedly giving a
         differentiated result for unusual characters)
    """
    if c in punctuation_set:
        return True
    if ord(c) <= 127:
        return False
    return None


cdef frozenset whitespace_set = frozenset({" ", "\n", "\t", "\r"})


cpdef int is_whitespace(str c):
    return c in whitespace_set
