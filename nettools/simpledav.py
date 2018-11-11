
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


import base64
import dateutil.parser
import dateutil.tz
import dateutil.utils
import html
import io
import nettools
import os
import textwrap
import time
import urllib.parse
from nettools.htmlparse import parse_xml

def as_bytes(v):
    try:
        return v.encode("utf-8", "replace")
    except AttributeError:
        return v

def webdav_path_joiner(p1, p2):
    p1 = as_bytes(p1)
    p2 = as_bytes(p2)
    if not p1.endswith(b"/") and \
            not p2.startswith(b"/"):
        return p1 + b"/" + p2
    return p1 + p2

def headers_value(headers, name):
    def get_header_name(header):
        try:
            header = header.decode("utf-8", "replace")
        except AttributeError:
            pass
        return str(header).partition(":")[0].lower()
    for header in headers:
        if get_header_name(header).lower() == name.lower():
            return header.partition(b":")[2].lstrip()
    return None

class DAVLocation(object):
    @staticmethod
    def from_options(host, port="default",
            dav_path=b"/",
            tls=True,
            tls_custom_chain_file=None):
        protocol = "http://"
        if tls:
            if port == "default":
                port = 443
            protocol = "https://"
        elif port == "default":
            port = 80
        if host.find("/") > 0 or host.find(" ") > 0:
            raise RuntimeError("invalid host")
        if host.find(":") > 0:
            host = "[" + host + "]"
        return DAVLocation(protocol +
            host + ":" + str(port) + "/" +
            urllib.parse.quote(dav_path),
            tls_custom_chain_file=tls_custom_chain_file)

    def __init__(self, url, tls_custom_chain_file=None):
        url_result = urllib.parse.urlparse(url)
        self.user_agent = "python-nettools-simpledav/0.1"
        self.host = url_result.hostname
        self.port = url_result.port
        self.password = url_result.password
        if self.password != None and len(self.password) == 0:
            self.password = None
        self.user = url_result.username
        if self.user != None and len(self.user) == 0:
            self.user = None
        if self.port is None:
            if url_result.scheme.lower() == "http":
                self.port = 80
            else:
                self.port = 443
        self.tls = (url_result.scheme.lower() != "http")
        self.tls_custom_chain_file = tls_custom_chain_file
        self.dav_path = url_result.path
        try:
            self.dav_path.decode("utf-8", "replace")
        except AttributeError:
            pass
        while self.dav_path.find("//") >= 0:
            self.dav_path = self.dav_path.replace("//", "/")
        self._basic_auth_realm = None
        self._supported_methods = None
        self._cached_path_info = dict()

    @property
    def supported_methods(self):
        if self._supported_methods != None:
            return self._supported_methods
        options = self._fetch_options()
        self._supported_methods = options["methods"]
        return self._supported_methods

    def _fetch_options(self):
        (response_headers, response_obj) = self.do_request(
            "OPTIONS", self.dav_path,
            textwrap.dedent("""\
                <?xml version="1.0" encoding="utf-8"?>
                <D:propfind xmlns:D="DAV:">
                  <D:prop>
                    <D:getlastmodified/>
                    <D:getcontentlength/>
                    <D:resourcetype/>
                  </D:prop>
                </D:propfind>"""))
        response = response_obj.read(1024 * 10)
        response_obj.close()
        if response_headers[0][1] == 405:
            raise OSError("got 405 method not allowed - " +
                "is your webdav url correct?")
        if headers_value(response_headers[1:], "allow") is None:
            raise OSError("protocol error: " +
                "missing 'Allow' header in OPTIONS request")
        def as_list(headerkey):
            v = headers_value(response_headers[1:], headerkey)
            if v is None:
                return []
            try:
                v = v.decode("utf-8", "replace")
            except AttributeError:
                pass
            v = [entry.strip().lower() for entry in
                v.split(",") if len(entry.strip()) > 0]
            return v
        result = {
            "methods": [e.upper() for e in as_list('Allow')],
            "dav": as_list("DAV")
        }

        # Work around a particular nextcloud weirdness:
        if "extended-mkcol" in result["dav"] and \
                not "MKCOL" in result["methods"]:
            result["methods"].append("MKCOL")
        return result

    def _parse_multistatus(self, xml_nodes):
        result = []
        for el in xml_nodes:
            if el.node_type == "element" and \
                    el.name.lower() == "d:multistatus":
                for child in el.children:
                    if child.node_type == "element" and \
                            child.name.lower() == "d:response":
                        result.append(child)
        return result

    def exists(self, file_path):
        info = self._get_path_info(file_path)
        if info is None:
            if not as_bytes(file_path).endswith(b"/"):
                info = self._get_path_info(as_bytes(file_path) + b"/")
                if info is None:
                    return False
            else:
                return False
        return True

    def open(self, file_path, mode="r", encoding="ascii",
            partial_range=None, progress_callback=None):
        # Sanity checks:
        if self.isdir(file_path):
            raise OSError("path is a directory")
        if not mode in ["r", "rb", "w", "wb"]:
            raise RuntimeError("mode not supported: '" + str(mode) + "'")
        if partial_range and mode in ["w", "wb"]:
            raise ValueError("partial_range not supported for mode '" +
                mode + "'")

        # Do it:
        if mode == "w":
            return self._open_for_writing(file_path,
                binary=False, encoding=encoding,
                progress_callback=progress_callback)
        elif mode == "wb":
            return self._open_for_writing(file_path,
                binary=True,
                progress_callback=progress_callback)
        elif mode == "rb" or mode == "r":
            return self._for_reading_open(file_path,
                binary=(mode == "rb"), encoding=encoding,
                partial_range=partial_range)
        else:
            raise RuntimeError("mode not supported")

    def _open_for_writing(self, file_path, binary=True,
            encoding="ascii", progress_callback=None):
        import tempfile
        (fd, fpath) = tempfile.mkstemp(
            prefix="trividav-upload-", suffix=".raw")
        os.close(fd)
        if binary:
            fhandle = open(fpath, "wb")
        else:
            fhandle = open(fpath, "w", encoding=encoding)
        dav_obj = self
        class Writer(object):
            def __init__(self):
                self.uploaded = False

            def __del__(self):
                self.close()
                try:
                    os.remove(fpath)
                except OSError:
                    pass

            def read(self):
                raise OSError("unsupported operation")

            def close(self):
                try:
                    fhandle.close()
                except OSError:
                    pass
                if self.uploaded:
                    return
                self.uploaded = True
                dav_obj._write_data(fpath, file_path,
                    progress_callback=progress_callback)
    
            def write(self, value):
                fhandle.write(value)
        return Writer()

    def _write_data(self, fpath, file_path, progress_callback=None):
        byte_amount = os.path.getsize(fpath)
        with open(fpath, "rb") as f:
            def report_progress(action, processed_bytes, total_bytes):
                if action != "send" or progress_callback is None:
                    return
                progress_callback(processed_bytes)
            (response_headers, response_obj) = self.do_request(
                "PUT", webdav_path_joiner(self.dav_path, file_path),
                f, headers=["Content-Length: " + str(byte_amount),
                "Content-Type: application/octet-stream"],
                progress_callback=report_progress)
            if response_headers[0][1] >= 400 and \
                    response_headers[0][1] < 600:
                raise OSError("server error: " +
                    " ".join([(str(t) if type(t) != bytes else
                    t.decode("utf-8", "replace")) for t \
                    in response_headers[0]]))
            response_obj.close()

    def _for_reading_open(self, file_path, binary=True,
            encoding="ascii", partial_range=None):
        extra_headers=[]
        if partial_range != None:
            if len(partial_range) != 2:
                raise ValueError("partial range must be a tuple " +
                    "with two values")
            start = int(partial_range[0])
            end = int(partial_range[1])
            if end <= start or start < 0:
                raise ValueError("requested invalid partial range")
            extra_headers.append(b"Range: bytes=" + str(
                start).encode("ascii") + b"-" + str(end).encode('ascii'))

        (response_headers, response_obj) = self.do_request(
            "GET", webdav_path_joiner(self.dav_path, file_path),
            headers=extra_headers,
            read_as_binary=binary, read_encoding=encoding)
        if partial_range != None:
            if response_headers[0][1] != 206:
                raise OSError("unexpected server response " +
                    str(response_headers[0]))
        else:
            if response_headers[0][1] != 200:
                raise OSError("unexpected server response " +
                    str(response_headers[0]))
        if binary:
            return response_obj
        else:
            # Hack to support this (otherwise, parsing half
            # characters out of the unfinished byte stream would
            # be too much of a mess):
            contents = response_obj.read()
            try:
                response_obj.close()
            except OSError:
                pass
            class WrapperReader(object):
                def __init__(self):
                    self.loaded = False

                def _load(self):
                    nonlocal contents
                    if self.loaded:
                        return
                    self.loaded = True
                    contents = contents.decode(encoding)
                    self.contents_wrapper = io.StringIO(contents)

                def writable(self):
                    return False

                def seekable(self):
                    return False

                def seek(self, *args):
                    raise OSError("operation not supported")

                def write(self, *args):
                    raise OSError("operation not supported")

                def close(self):
                    return

                def __getattr__(self, v):
                    self._load()
                    return getattr(self.contents_wrapper, v)
            return WrapperReader()

    def getmtime(self, file_path):
        info = self._get_path_info(file_path)
        if info is None:
            return None
        for entry in info:
            if len(entry[0]) == 0:
                if "last-modified" in entry[1]:
                    return entry[1]["last-modified"]
        return None

    def isdir(self, file_path):
        info = self._get_path_info(file_path)
        if info is None:
            return False
        result = []
        for entry in info:
            if len(entry[0]) == 0:
                if entry[1]["type"] != "directory":
                    return False
                return True
        return False

    def listdir(self, file_path):
        info = self._get_path_info(file_path)
        if info is None:
            return None
        result = []
        for entry in info:
            if len(entry[0]) == 0:
                if entry[1]["type"] != "directory":
                    return None
            else:
                if entry[0].find(b"/") < 0:
                    result.append(entry[0])
        return result

    def remove(self, file_path):
        if as_bytes(file_path).endswith(b"/"):
            raise OSError("path is a directory")
        listing = self.listdir(file_path)
        if listing != None:
            raise OSError("path is a directory")
        del_path = webdav_path_joiner(self.dav_path,
            file_path)
        if response_headers[0][1] == 204:
            return
        elif response_headers[0][1] == 404:
            raise RuntimeError("no such file or directory")
        else:
            raise OSError("unexpected response code, " +
                "deletion may have failed (code " +
                str(response_headers[0][1]) + ")")

    def rmdir(self, file_path, only_if_empty=True):
        listing = self.listdir(file_path)
        if listing is None and self.exists(file_path):
            raise OSError("not a directory")
        if only_if_empty and listing != None and \
                len(listing) > 0:
            raise OSError("directory not empty")
        del_path = webdav_path_joiner(self.dav_path,
            file_path)
        if not del_path.endswith(b"/"):
            del_path += b"/"
        (response_headers, response_obj) = self.do_request(
            "DELETE", del_path)
        if response_headers[0][1] == 204:
            return
        elif response_headers[0][1] == 404:
            if self.exists(file_path):
                # Exists without trailing slash -> a file.
                raise OSError("not a directory")
            raise RuntimeError("no such file or directory")
        else:
            raise OSError("unexpected response code, " +
                "deletion may have failed (code " +
                str(response_headers[0][1]) + ")")

    def mkdir(self, file_path):
        if not "MKCOL" in self.supported_methods:
            raise OSError("this server doesn't support " +
                "creating directories")
        (response_headers, response_obj) = self.do_request(
            "MKCOL", webdav_path_joiner(self.dav_path,
                file_path))
        if response_headers[0][1] == 201:
            return
        elif response_header[0][1] == 405:
            raise OSError("can't create directory here " +
                "- maybe the path exists already?")
        elif response_header[0][1] >= 400 and \
                response_headers[0][1]:
            raise OSError("server error: " +
                str(response_header[0]))
        else:
            raise OSError("unexpected response code, " +
                "creation may have failed (code " +
                str(response_headers[0][1]) + ")")

    def normalize_webdav_path(self, v):
        had_slash = False
        v = as_bytes(v)
        if v.endswith(b"/"):
            had_slash = True
        v = os.path.normpath(v.replace(b"/",
            os.path.sep.encode("utf-8"))).\
            replace(os.path.sep.encode("utf-8"), b"/")
        while v.find(b"//") >= 0:
            v = v.replace(b"//", b"/")
        if v.startswith(b"/"):
            v = v[1:]
        if had_slash and not v.endswith(b"/"):
            return v + b"/"
        return v

    def interpret_url_path(self, base_url, path_url):
        base = self.normalize_webdav_path(
            urllib.parse.unquote(base_url))
        path = self.normalize_webdav_path(
            urllib.parse.unquote(path_url))
        if path.startswith(base):
            path = path[len(base):]
        if path.startswith(b"/"):
            path = path[1:]
        return path

    def _get_path_info(self, path):
        path = self.normalize_webdav_path(path)
        if path in self._cached_path_info and \
                self._cached_path_info[path][1] + 5.0 >\
                time.monotonic():
            return self._cached_path_info[path][0]
        if not "PROPFIND" in self.supported_methods:
            raise OSError("this server is not supported, " +
                "lacks PROPFIND command")
        (response_headers, response_obj) = self.do_request(
            "PROPFIND", webdav_path_joiner(self.dav_path, path),
            textwrap.dedent("""\
                <?xml version="1.0" encoding="utf-8"?>
                <D:propfind xmlns:D="DAV:">
                  <D:prop>
                    <D:getlastmodified/>
                    <D:getcontentlength/>
                    <D:resourcetype/>
                  </D:prop>
                </D:propfind>"""))
        base_url = urllib.parse.quote(
            webdav_path_joiner(self.dav_path, path))
        response = response_obj.read(1024 * 10)
        response_obj.close()
        result = []
        if response_headers[0][1] == 207:  # multistatus
            responses = parse_xml(response)
            if len(responses) >= 1 and \
                    responses[0].node_type == "element" and \
                    responses[0].name.lower() == "?xml":
                responses = responses[0].children
            for response in self._parse_multistatus(responses):
                response_entry = None
                response_size = None
                response_restype = None
                response_last_modified = None
                def process_prop(prop):
                    nonlocal response_restype, response_last_modified,\
                        response_size
                    if prop.node_type == "element" and \
                            prop.name.lower() == "d:resourcetype":
                        response_restype = "file"
                        for child in prop.children:
                            if child.node_type == "element" and \
                                    child.name.lower() == "d:collection":
                                response_restype = "directory"
                    elif prop.node_type == "element" and \
                            prop.name.lower() == "d:getlastmodified":
                        inner = prop.serialize_children()
                        if inner.find("<") < 0 and inner.find(">") < 0:
                            response_last_modified = \
                                dateutil.utils.default_tzinfo(
                                dateutil.parser.parse(
                                html.unescape(inner)), dateutil.tz.UTC)
                    elif prop.node_type == "element" and \
                            prop.name.lower() == "d:getcontentlength":
                        contents = prop.serialize_children()
                        try:
                            contents = max(0, int(contents))
                            response_size = contents
                        except (TypeError, ValueError):
                            pass
                for child in response.children:
                    # Go through all element responses:
                    if child.node_type == "element" and \
                            child.name.lower() == "d:href":
                        # The file the response refers to
                        response_entry = self.interpret_url_path(
                            base_url, html.unescape(
                            child.serialize_children()))
                    elif child.node_type == "element" and \
                            child.name.lower() == "d:propstat":
                        # A property! See if it has a success code:
                        no_value = False
                        for inner_child in child.children:
                            if inner_child.node_type == "element" and \
                                    inner_child.name.lower() == "d:status":
                                if inner_child.serialize_children().\
                                        upper().find(" 200 ") < 0:
                                    no_value = True
                                break
                        if no_value:
                            continue
                        # Property has success code. Process actual value:
                        for inner_child in child.children:
                            if inner_child.node_type == "element" and \
                                    inner_child.name.lower() == "d:prop":
                                for inner_inner_child in \
                                        inner_child.children:
                                    process_prop(inner_inner_child)
                if response_entry is None:
                    continue
                if as_bytes(response_entry).endswith(b"/"):
                    response_entry = as_bytes(response_entry)[:-1]
                result.append((response_entry, {
                    "size": response_size,
                    "type": response_restype,
                    "last-modified": response_last_modified}))
        elif response_headers[0][1] == 404:
            result = None
        else:
            raise OSError("protocol error: " +
                "unexpected response code: " +
                str(response_headers[0][1]))
        self._cached_path_info[path] = (result, time.monotonic())
        return result

    def do_request(self, verb, location,
            body=b"", headers=[], follow_redirects=3,
            read_as_binary=True, read_encoding=None,
            debug=False):
        location = as_bytes(location)
        if len(location) == 0:
            location = b"/"
        while location.find(b"//") >= 0:
            location = location.replace(b"//", b"/")
        try:
            verb = verb.decode("utf-8", "replace")
        except AttributeError:
            pass
        def fix_broken_urlquote(v):
            return as_bytes(urllib.parse.quote(v))
        headers = [verb.encode("utf-8", "replace") + b" " +
            fix_broken_urlquote(location) + b" HTTP/1.1"] + headers
        def get_header_name(header):
            try:
                header = header.decode("utf-8", "replace")
            except AttributeError:
                pass
            return header.partition(":")[0].lower()
        def got_header(name):
            for header in headers:
                if get_header_name(header).lower() == name.lower():
                    return True
            return False
        if not got_header("User-Agent"):
            headers.append("User-Agent: " + str(self.user_agent))
        if not got_header("Content-Length") and len(body) > 0:
            headers.append("Content-Length: " + str(len(body)))
        if not got_header("Accept-Encoding"):
            headers.append(b"Accept-Encoding: identity")
        if not got_header("Connection"):
            headers.append(b"Connection: close")
        if not got_header(b"Accept"):
            headers.append(b"Accept: */*")
        if not got_header(b"Transfer-Encoding"):
            headers.append(b"Transfer-Encoding: identity")
        if not got_header(b"Host"):
            headers.append("Host: " + str(self.host))
        if not got_header(b"Authorization") and (
                self.user != None and self.password != None and
                self._basic_auth_realm != None):
            upw = as_bytes(self.user) + b":" + as_bytes(self.password)
            headers.append(b"Authorization: Basic " +
                base64.b64encode(upw))

        if debug:
            print("nettools.simpledav.DAVLocation.do_request: " +
                "all headers: " + str([(header if
                str(header).lower().find("authorization") < 0 else
                "<AUTHORIZATION HEADER HIDDEN>") for header in headers]))
        (response_headers, body_obj) = nettools.do_http_style_request(
            self.host, self.port,
            tls_enabled=self.tls,
            tls_extra_chain_path=self.tls_custom_chain_file,
            send_headers=headers, send_body=body,
            operations_timeout=10,
            auto_evaluate_chunked_encoding=True,
            auto_evaluate_content_size=True)
        def response_header_value(name):
            for header in response_headers[1:]:
                if get_header_name(header).lower() == name.lower():
                    return header.partition(b":")[2].lstrip()
            return None
        if follow_redirects > 0 and response_headers[0][1] == 302 and \
                 response_header_value("Location") != None:
            loc = response_header_value("Location")
            urlloc = urllib.parse.urlparse(loc)
            if hasattr(body, "read"):
                body.seek(0)  # revert to file start
            return self.do_request(verb, urlloc.path, body,
                headers=headers[1:], follow_redirects=(
                follow_redirects-1))
        elif response_headers[0][1] == 401:
            if response_header_value("WWW-Authenticate") is None:
                raise OSError("protocol error: got permission denied, " +
                    "but no WWW-Authenticate header!")
            if self.user is None or self.password is None or \
                    self._basic_auth_realm != None:
                if self._basic_auth_realm != None:
                    raise PermissionError("incorrect login")
                raise PermissionError("user and password required")
            extract_realm = \
                response_header_value("WWW-Authenticate").strip()
            try:
                extract_realm = extract_realm.encode("utf-8", "replace")
            except AttributeError:
                pass
            if extract_realm.lower().startswith(b"basic realm="):
                extract_realm = extract_realm[len(b"basic realm="):]
            if extract_realm.startswith(b"\"") and \
                    extract_realm.endswith(b"\""):
                extract_realm = extract_realm[1:-1]
            if len(extract_realm) > 0:
                self._basic_auth_realm = extract_realm
            else:
                raise OSError("protocol error: got permission denied, " +
                    "but no authentication realm")
            if hasattr(body, "read"):
                body.seek(0)  # revert to file start
            return self.do_request(verb, location, body,
                headers=headers[1:], follow_redirects=(
                follow_redirects-1))
        return (response_headers, body_obj)

