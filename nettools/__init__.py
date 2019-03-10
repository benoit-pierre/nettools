
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

import ipaddress
import os
import random
import socket
import time

def is_metered():
    try:
        from jnius import autoclass
    except ImportError:
        return False

    Activity = autoclass('android.app.Activity')
    PythonActivity = autoclass('org.renpy.android.PythonActivity')
    activity = PythonActivity.mActivity
    ConnectivityManager = autoclass('android.net.ConnectivityManager')

    con_mgr = activity.getSystemService(Activity.CONNECTIVITY_SERVICE)

    if con_mgr.getNetworkInfo(ConnectivityManager.TYPE_WIFI).\
            isConnectedOrConnecting():
        return False
    if con_mgr.getNetworkInfo(ConnectivityManager.TYPE_MOBILE).\
            isConnectedOrConnecting():
        return True
    return False

def dns_lookup(name, single_target=True):
    last_error = None
    def dns_lookup_multitarget(name):
        nonlocal last_error
        try:
            ip = ipaddress.ip_address(name)
            # If we arrived here, it's a valid ip already.
            return [str(ip)]
        except ValueError:
            pass
        try:
            result = socket.getaddrinfo(
                name, None, socket.AF_INET6)
            if len(result) > 0:
                return [str(entry[4][0]) for entry in result]
        except socket.gaierror as e:
            last_error = e
            try:
                result = socket.getaddrinfo(
                    name, None, socket.AF_INET)
            except socket.gaierror as e:
                last_error = e
                return []
            if len(result) > 0:
                return [str(entry[4][0]) for entry in result]
    targets = dns_lookup_multitarget(name)
    assert(targets != None)
    if single_target:
        if len(targets) > 0:
            return random.choice(targets)
        assert(last_error != None)
        raise last_error
    return targets

_contexts = dict()
def get_tls_context(unsafe_legacy, system_certs, extra_chain_path):
    global _contexts
    settings_key = (unsafe_legacy, system_certs, extra_chain_path)
    if settings_key in _contexts:
        return _contexts[settings_key]
    try:
        import ssl
    except ImportError:
        raise OSError("missing ssl module, can't " +
            "connect using TLS")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    if not unsafe_legacy:
        client_context.options |= ssl.OP_NO_TLSv1
    if extra_chain_path != None:
        if not os.path.exists(extra_chain_path):
            raise OSError("non-existing file specified " +
                "as extra chain path: " + str(extra_chain_path))
        try:
            client_context.load_verify_locations(
                cafile=extra_chain_path)
        except Exception as e:
            raise OSError("failed to load cert file specified " +
                "at: " + str(extra_chain_path))
    if system_certs:
        client_context.load_default_certs()
    _contexts[settings_key] = client_context
    return client_context

class SimpleTCPClient(object):
    def __init__(self, host, port, tls_enabled=False,
            tls_support_unsafe_legacy=False,
            tls_use_system_certificates=True):
        self.socket = None
        self.host = host
        self._target = None
        self._target_resolve_failed = False
        self.port = int(port)
        self.operations_timeout = 10
        self.tls_enabled = tls_enabled
        self.tls_support_unsafe_legacy = tls_support_unsafe_legacy
        self.tls_use_system_certificates = tls_use_system_certificates
        self.tls_extra_chain_path = None
        self._connection = None

    def set_custom_tls_certificate_chain(self, chains,
            disable_system_certs=True):
        if not self.tls_enabled:
            raise ValueError("cannot use this " +
                "option when not using TLS")
        if self.socket != None:
            raise OSError("already connected, changing " +
                "setting now is not implemented")
        self.tls_extra_chain_path = chains
        if disable_system_certs:
            self.tls_use_system_certificates = False

    @property
    def target(self):
        if self._target is None:
            if not self._target_resolve_failed:
                try:
                    self._target = dns_lookup(self.host)
                except Exception as e:
                    self._target_resolve_failed = True
                    raise e
        return self._target

    def close(self):
        if self.socket != None:
            try:
                self.socket.close()
            except OSError:
                pass
            self.socket = None

    def connect(self):
        if self.socket != None:
            return
        if self.tls_enabled and self.tls_extra_chain_path is None and \
                not self.tls_use_system_certificates:
            raise ValueError("INVALID OPTIONS: " +
                "no custom chain path set for TLS, " +
                "but system certificates are also disabled. " +
                "Impossible to establish a verified connection!")
        context = None
        if self.tls_enabled:
            context = get_tls_context(
                self.tls_support_unsafe_legacy,
                self.tls_use_system_certificates,
                self.tls_extra_chain_path)
        target = self.target
        self.socket = None
        if target.find(":") > 0:
            # IPv6
            self.socket = socket.socket(socket.AF_INET6,
                socket.SOCK_STREAM)
        else:
            # IPv4
            self.socket = socket.socket(socket.AF_INET,
                socket.SOCK_STREAM)
        if self.tls_enabled:
            self.socket = context.wrap_socket(self.socket,
                server_hostname=self.host)
        try:
            self.socket.settimeout(self.operations_timeout)
            self.socket.connect((target, self.port))
        except Exception as e:
            self.close()
            import ssl
            if self.tls_enabled and isinstance(e, ssl.SSLError):
                print("ERROR: Got ssl faillure, config info: " +
                    str({"tls_extra_chain_path":
                        self.tls_extra_chain_path,
                        "tls_use_system_certificates":
                        self.tls_use_system_certificates,
                        "tls_support_unsafe_legacy":
                        self.tls_support_unsafe_legacy}))
            raise e

    def write(self, msg):
        if self.socket is None:
            raise OSError("disconnected")
        if type(msg) != bytes and type(msg) != bytearray:
            msg = str(msg)
        try:
            msg = msg.encode("utf-8", "replace")
        except AttributeError:
            pass
        length_msg = len(msg)
        bytes_sent = 0
        while bytes_sent < length_msg:
            self.socket.settimeout(self.operations_timeout)
            result = self.socket.send(msg)
            if result == 0:
                self.close()
                raise OSError("disconnected (incomplete send)")
            bytes_sent += result
        return bytes_sent

    def readline(self, max_length=(1024 * 10),
            error_when_length_exceeded=True):
        result = b""
        c = None
        while c != b"\n":
            if max_length != None and \
                    len(result) >= max_length and \
                    error_when_length_exceeded:
                raise OSError("maximum line length exceeded")
            c = self.read(1)
            result += c
        if result.endswith(b"\r\n"):
            result = result[:-2]
        elif result.endswith(b"\n"):
            result = result[:1]
        return result

    def read(self, amount=None):
        if self.socket is None:
            raise OSError("disconnected")
        result = b""
        bytes_received = 0
        while amount is None or bytes_received < amount:
            self.socket.settimeout(self.operations_timeout)
            value = self.socket.recv(min(512, amount - bytes_received))
            if len(value) == 0:
                self.close()
                if len(result) == 0:
                    raise OSError("disconnected")
                return result
            bytes_received += len(value)
            result += value
        return result

def do_http_style_request(host, port,
        tls_enabled=False,
        tls_support_unsafe_legacy=False,
        tls_use_system_certificates=True,
        tls_extra_chain_path=None,
        tls_dont_use_system_certs_if_extra_chain=True,
        send_headers=[], send_body=b"",
        operations_timeout=10,
        auto_evaluate_chunked_encoding=True,
        auto_evaluate_content_size=True,
        progress_callback=None):
    if tls_extra_chain_path != None:
        if tls_dont_use_system_certs_if_extra_chain:
            tls_use_system_certificates = False
    client = SimpleTCPClient(host, port,
        tls_enabled=tls_enabled,
        tls_support_unsafe_legacy=tls_support_unsafe_legacy,
        tls_use_system_certificates=tls_use_system_certificates)
    if tls_extra_chain_path != None:
        client.set_custom_tls_certificate_chain(
            tls_extra_chain_path,
            disable_system_certs=False)
    client.operations_timeout = operations_timeout 
    client.connect()
    def as_bytes(v):
        try:
            return v.encode("utf-8", "replace")
        except AttributeError:
            return v
    if len(send_headers) > 0:
        client.write(b"\r\n".join(
                [as_bytes(l) for l in send_headers]) +
                b"\r\n\r\n")

    # Send client body:
    chunk_size = 1024 * 4
    send_total = None
    send_current = 0
    last_progress_update = time.monotonic() - 2
    def send_progress_update():
        nonlocal last_progress_update
        if last_progress_update + 0.5 < time.monotonic():
            last_progress_update = time.monotonic()
            if progress_callback != None:
                progress_callback(
                    "send", send_current, send_total)
    if hasattr(send_body, "read"):
        # File like object:
        while True:
            content = send_body.read(chunk_size)
            if len(content) == 0:
                break
            try:
                content = content.encode("utf-8", "replace")
            except AttributeError:
                pass
            client.write(content)
            send_current += len(content)
            send_progress_update()
    else:
        send_bytes = as_bytes(send_body)
        send_total = len(send_bytes)
        while len(send_bytes) > 0:
            client.write(send_bytes[:chunk_size])
            send_current += len(send_bytes[:chunk_size])
            send_bytes = send_bytes[chunk_size:]
            send_progress_update()

    # Drop what we no longer need:
    del(send_body)
    try:
        del(send_bytes)
    except NameError:
        pass

    # Get response headers:
    received_response = None
    received_headers = []
    recv_total = None
    recv_current = 0
    def recv_progress_update():
        nonlocal last_progress_update
        if last_progress_update + 1 < time.monotonic():
            last_progress_update = time.monotonic()
            if progress_callback != None:
                progress_callback(
                    "receive", recv_current, recv_total)
    while True:
        line = client.readline(max_length=1024)
        if len(line) > 0:
            if received_response is None:
                received_response = line.split(b" ")
                if len(received_response) > 3:
                    received_response = received_response[:2] +\
                        [b" ".join(received_response[2:])]
                if len(received_response) < 2:
                    received_response += [-1]
                try:
                    received_response[1] = int(received_response[1])
                except (TypeError, ValueError):
                    pass
                continue
            received_headers.append((
                line.partition(b":")[0].strip(),
                line.partition(b":")[2].lstrip()))
            if len(received_headers) > 256:
                raise OSError("aborting due to excessive amount of headers")
        else:
            break
    content_size = None
    chunked_transfer = False

    # Evaluate content-length and chunked transfer encoding if told so:
    if auto_evaluate_content_size:
        for (k, v) in received_headers:
            if k.decode("utf-8", "replace").lower() == "content-length":
                try:
                    content_size = int(v.decode("utf-8", "replace").strip())
                    recv_total = content_size
                except (ValueError, TypeError):
                    pass
    if auto_evaluate_chunked_encoding:
        for (k, v) in received_headers:
            if k.decode("utf-8", "replace").lower() == "transfer-encoding":
                if v == "chunked":
                    chunked_transfer = True

    # Get contents:
    read_state = {"content-size-left": content_size,
        "content-size-total": content_size,
        "chunk-data-left": 0, "chunked": chunked_transfer}
    def read_contents(amount):
        nonlocal read_state
        if read_state["content-size-left"] != None:
            amount = min(amount, read_state["content-size-left"])
        if amount == 0:
            return b""
        content = None
        if not read_state["chunked"]:
            content = client.read(amount)
            if read_state["content-size-left"] != None and \
                    len(content) < amount:
                client.close()
                raise OSError("incomplete response")
            if read_state["content-size-left"] != None:
                read_state["content-size-left"] -= len(content)
            return content
        else:
            content = b""
            while amount > 0:
                if read_state["chunk-data-left"] <= 0:
                    next_chunk_size = client.readline(32)
                    try:
                        next_chunk_size = int(next_chunk_size.strip(), 16)
                    except (ValueError, TypeError):
                        client.close()
                        raise OSError("response with invalid HTTP chunk")
                    if next_chunk_size == 0:
                        client.close()
                        if read_state["content-size-left"] != None:
                            if read_state["content-size-left"] > 0:
                                raise OSError("incomplete response")
                        return b""
                    read_state["chunk-data-left"] = amount
                chunk_amount = min(read_state["chunk-data-left"], amount)
                next_chunk = client.read(chunk_amount)
                if len(next_chunk) < chunk_amount:
                    raise OSError("incomplete response")
                read_state["chunk-data-left"] -= chunk_amount
                amount -= chunk_amount
                content += next_chunk
                if read_state["content-size-left"] != None:
                    read_state["content-size-left"] -= chunk_amount
            return content
    class SimpleStreamObj(object):
        def __init__(self):
            self.stream_pos = 0
            self.is_readable = True
            self.reported_nonreadable = False

        @property
        def closed(self):
            return (not self.is_readable)

        @property
        def len(self):
            nonlocal read_state
            if "content-size-total" in read_state and \
                    read_state["content-size-total"] is not None:
                return max(0, int(read_state["content-size-total"]))
            raise ValueError("no content length available")

        def fileno(self):
            raise NotImplementedError("operation not supported")

        def isatty(self):
            return False

        def flush(Self):
            return

        def close(self):
            client.close()
            self.is_readable = False

        def read(self, size=None):
            nonlocal recv_current
            if not self.is_readable:
                if not self.reported_nonreadable:
                    self.reported_nonreadable = True
                    return b""
                else:
                    raise OSError("stream is closed")
            if size == 0:
                return b""
            result = b""
            while size is None or size > 0:
                read_amount = chunk_size
                if size != None:
                    read_amount = min(read_amount, size)
                addition = read_contents(read_amount)
                if len(addition) == 0:
                    self.is_readable = False
                    if len(result) > 0:
                        self.reported_nonreadable = False
                    else:
                        self.reported_nonreadable = True
                    break
                if size != None:
                    size -= len(addition)
                recv_current += len(addition)
                result += addition
            self.stream_pos += len(result)
            recv_progress_update()
            return result

        def readline(self, size=-1):
            c = None
            result = b""
            while c != b"\n":
                c = self.read(size=1)
                if len(c) == 0:
                    return result
                result += c
            return result

        def readlines(Self, hint=-1):
            lines = []
            bytes_read = 0
            while True:
                line = self.readline()
                bytes_read += len(line)
                if len(line) > 0:
                    lines.append(line)
                if self.closed or len(line) == 0:
                    self.is_readable = False
                    return lines
                if hint >= 0 and bytes_read > hint:
                    return lines

        def readable(self):
            return self.is_readable

        def seek(self, offset, whence=0):
            self.trigger_write_error()

        def seekable(self):
            return False

        def truncate(self, size=None):
            self.trigger_write_error()

        def tell(self):
            return self.stream_pos

        def read1(self, size):
            return self.read(size=size)

        def readinto(self, byte_array):
            amount = len(byte_array)
            if amount == 0:
                return
            content = self.read(size=amount)
            if len(content) > 0:
                byte_array[:min(amount, amount_read)] = content
            return len(content)

        def writable(self):
            return False

        def readinto1(self, byte_array):
            return self.readinto(byte_array)

        def writelines(self, lines):
            self.trigger_write_error()

        def write(self, data):
            self.trigger_write_error()

        def trigger_write_error(self):
            raise OSError("this is a request body " +
                "response stream, no writing supported")

    result = ([received_response] +
        [k + b": " + v for (k, v) in received_headers[1:]],
        SimpleStreamObj())
    return result

def get_request(url, user_agent="nettool/0.1"):
    import urllib.parse
    url_result = urllib.parse.urlparse(url)
    host = url_result.hostname
    port = url_result.port
    if port is None:
        if url_result.scheme.lower() == "http":
            port = 80
        else:
            port = 443
    tls = (url_result.scheme.lower() != "http")
    path = url_result.path
    if len(path.strip()) == 0:
        path = "/" 
    (headers, file_obj) = do_http_style_request(
        host, int(port),
        tls_enabled=tls,
        send_headers=["GET " +
        str(urllib.parse.quote(path)) +
        " HTTP/1.1", "Host: " + str(host),
        "User-Agent: " + str(user_agent),
        "Transfer-Encoding: identity",
        "Accept-Encoding: identity",
        "Content-Length: 0"],
        send_body=b"",
        operations_timeout=10,
        auto_evaluate_chunked_encoding=True,
        auto_evaluate_content_size=True)

