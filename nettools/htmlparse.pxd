
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


cpdef parse_xml(xml)

cpdef parse(html, void_tags=*)

cpdef str remove_html_comments(str t)

cpdef str linkify_html(str html_text, int linkify_with_blank_target=*)

cpdef depth_first_walker(html, callback, visit_out_callback=*)

cpdef str remove_html_comments(str t)
