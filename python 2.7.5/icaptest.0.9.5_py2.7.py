import socket
import ssl
import os
import argparse
import sys
import re
import threading
from urlparse import urlparse
import traceback
#import requests

BASE64_LINE_RE = re.compile(r'^[A-Za-z0-9+/]+={0,2}$')
BASE64_INLINE_RE = re.compile(r'(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{120,}={0,2})(?![A-Za-z0-9+/=])')
DATA_URI_BASE64_RE = re.compile(r'(;base64,)([A-Za-z0-9+/=\s]{120,})', re.IGNORECASE)


def filter_base64_output(response_text):
    """Mask long base64 content in output to keep terminal/UI output readable."""
    if not response_text:
        return response_text

    # Collapse long data URI base64 payloads first.
    response_text = DATA_URI_BASE64_RE.sub(r'\1[base64 content omitted]', response_text)
    # Then collapse other long inline base64 blobs.
    response_text = BASE64_INLINE_RE.sub('[base64 content omitted]', response_text)

    filtered_lines = []
    for line in response_text.splitlines():
        candidate = line.strip()
        if len(candidate) >= 120 and len(candidate) % 4 == 0 and BASE64_LINE_RE.fullmatch(candidate):
            if not filtered_lines or filtered_lines[-1] != "[base64 content omitted]":
                filtered_lines.append("[base64 content omitted]")
            continue
        filtered_lines.append(line)

    return "\n".join(filtered_lines)


def sanitize_response_output(response):
    """Normalize and sanitize response objects for display."""
    #print("sanitize:" + str(response))
    if response is None:
        return None
    if not isinstance(response, str):
        if(isinstance(response, unicode)):
           response = response.encode('utf-8')
        response = str(response)
    return filter_base64_output(response)


class IcapClient:
    def __init__(self, server_address, server_port, use_tls=False, accept_early_204=False, ignore_cert_errors=False, enforce_srv_cert=True, preview=None, timeout=60, api_key=None):
        self.server_address = server_address
        self.server_port = server_port
        self.use_tls = use_tls
        self.accept_early_204 = accept_early_204
        self.ignore_cert_errors = ignore_cert_errors
        self.enforce_srv_cert = enforce_srv_cert
        self.buffer_size = 1024
        self.preview = preview
        self.timeout = timeout
        self.api_key = api_key

    def send_request(self, icap_method, icap_service, headers=None, body=None, http_request=None):
        try:
            s = socket.create_connection((self.server_address, self.server_port), timeout=self.timeout)
            if self.use_tls:
                try:
                    context = ssl.create_default_context()
                    if self.ignore_cert_errors:
                        context.check_hostname = False
                        context.verify_mode = ssl.CERT_NONE
                    s = context.wrap_socket(s, server_hostname=self.server_address, do_handshake_on_connect=False)
                    s.settimeout(self.timeout)
                    s.do_handshake()
                except (socket.timeout, ssl.SSLError) as e:
                    s.close()
                    return "TLS Connection failed: " + str(e)

            if self.preview is not None and icap_method != 'OPTIONS':
                headers['Preview'] = str(self.preview)

            request_line = icap_method + " icap://" + self.server_address + icap_service + " ICAP/1.0\r\n"
            header_lines = "\r\n".join([k+": "+v for k, v in headers.items()])

            s.sendall((request_line + header_lines +"\r\n\r\n").encode('utf-8'))

            http_request and s.sendall(http_request.encode('utf-8'))

            response = self._send_chunked_body(s, body) if body else self._receive_response(s)

            s.close()
            return response

        except socket.timeout:
            return "Connection timed out after "+ self.timeout + " seconds to "+ self.server_address + str(self.server_port)
        #except ConnectionRefusedError:
            #return "Connection refused by "+ self.server_address + str(self.server_port)
        except Exception as e:
            print("Error sending request: "+ str(e) + traceback.format_exc(e))
            return "Error sending request: "+ str(e) 

    def _send_chunked_body(self, s, body):
        def send_chunks(sock, data, chunk_size=1024):
            """Send data in ICAP chunked-encoding format."""
            remaining = data
            while remaining:
                chunk = remaining[:chunk_size]
                remaining = remaining[chunk_size:]
                sock.sendall(hex(len(chunk))[2:].upper() + "\r\n".encode('utf-8'))
                sock.sendall(chunk)
                sock.sendall(b"\r\n")
            sock.sendall(b"0\r\n\r\n")

        body = bytearray(body)

        # ---- PREVIEW MODE ----
        if self.preview is not None:

            # ---------------- preview = 0 ----------------
            if self.preview == 0:
                s.sendall(b"null-body\r\n\r\n")

                response = self._receive_response(s)
                if not response.startswith("ICAP/1.0 100"):
                    return response

                # send full body after continue
                send_chunks(s, body)

            # ---------------- preview > 0 ----------------
            else:
                preview_chunk = body[:self.preview]

                # send preview
                s.sendall(hex(len(chunk))[2:].upper() + "\r\n".encode('utf-8'))
                s.sendall(preview_chunk)
                s.sendall(b"\r\n")

                # send preview terminator
                if len(body) <= self.preview:
                    s.sendall(b"0; ieof\r\n\r\n")
                    return self._receive_response(s)
                else:
                    s.sendall(b"0;\r\n\r\n")

                # wait for continue
                response = self._receive_response(s)
                print(sanitize_response_output(response))
                if not response.startswith("ICAP/1.0 100"):
                    return response

                # send remaining body
                send_chunks(s, body[self.preview:])

        # ---- NO PREVIEW ----
        else:
            send_chunks(s, body)

        return self._receive_response(s)

    def _receive_response(self, s):
        s.settimeout(self.timeout)
        data = b""
        try:
            while b"\r\n\r\n" not in data:
                chunk = s.recv(1)
                if not chunk: break
                data += chunk
            header_part = data.split(b"\r\n\r\n")[0].decode('utf-8', errors='ignore')
            content_length = None
            is_chunked = False
            for line in header_part.split('\r\n'):
                if line.lower().startswith('content-length:'):
                    content_length = int(line.split(':',1)[1].strip())
                elif line.lower().startswith('transfer-encoding:') and 'chunked' in line.lower():
                    is_chunked = True

            if is_chunked:
                while True:
                    chunk_size_line = b""
                    while not chunk_size_line.endswith(b"\r\n"):
                        byte = s.recv(1)
                        if not byte: break
                        chunk_size_line += byte
                    if not chunk_size_line: break
                    try:
                        chunk_size_val = int(chunk_size_line.strip().decode(), 16)
                    except ValueError:
                        break
                    if chunk_size_val == 0:
                        s.recv(2)
                        break
                    chunk_data = b""
                    while len(chunk_data) < chunk_size_val:
                        chunk = s.recv(min(chunk_size_val-len(chunk_data), self.buffer_size))
                        if not chunk: break
                        chunk_data += chunk
                    data += chunk_data
                    s.recv(2)
            elif content_length is not None:
                body_start = len(data)
                remaining = content_length - (len(data) - data.find(b"\r\n\r\n") - 4)
                while remaining > 0:
                    chunk = s.recv(min(remaining, self.buffer_size))
                    if not chunk: break
                    data += chunk
                    remaining -= len(chunk)
            else:
                s.settimeout(1.0)
                try:
                    while True:
                        chunk = s.recv(self.buffer_size)
                        if not chunk: break
                        data += chunk
                except socket.timeout:
                    pass
        except Exception as e:
            if not data:
                return "Error receiving response: " + str(e)
        return sanitize_response_output(data.decode('utf-8', errors='ignore'))

    def adapt_content(self, content=None, icap_service='/reqmod', method='REQMOD', url=None, req_method='POST'):
        # Initialize base headers
        headers = {
            'Host': self.server_address,
            'User-Agent': 'IcapClient/1.0',
            'Allow': '204' if self.accept_early_204 else None,
            'Transfer-Encoding': 'chunked' if content else None
        }
        if self.api_key:
            headers['Authorization'] = "Basic " + self.api_key
        headers = {k:v for k,v in headers.items() if v}

        http_message = None
        body = None

        if method == 'REQMOD':
            headers, http_message = self._handle_reqmod(content, url, req_method, headers)
            body = content
        elif method == 'RESPMOD':          
            headers, http_message, body = self._handle_respmod(content, url, headers)

        response = self.send_request(method, icap_service, headers, body, http_message)
        return response

    def _handle_reqmod(self, content, url, req_method, headers):
        if not url and not content:
            raise ValueError('REQMOD without a file requires a URL')

        url = url or ('/upload' if content else url)
        parsed = urlparse(url)
        path = parsed.path or '/'
        path += "?" + parsed.query

        if content:
            http_message = self._build_content_message(req_method, path, parsed, content)
            headers['Encapsulated'] = "req-hdr=0, req-body="+str(len(http_message))
        else:
            http_message = self._build_url_message(path, parsed)
            headers['Encapsulated'] = "req-hdr=0, null-body="+str(len(http_message))

        return headers, http_message

    def _handle_respmod(self, content, url, headers):
        if not url:
            raise ValueError('RESPMOD requires a URL')

        parsed = urlparse(url)
        path = (parsed.path or '/') + "?" + parsed.query

        http_message = self._build_url_message(path, parsed)
        req_hdr_len = len(http_message.encode('utf-8'))

        if not content:
            http_response = requests.get(url, verify=self.enforce_srv_cert)
            body = http_response.content
            http_message = http_message + self._build_respmod_message(http_response)
        else:
            body = content
            http_message = http_message + self._build_respmod_message()
        
        res_hdr_len = len(http_message.encode('utf-8'))

        headers['Encapsulated'] = "req-hdr=0, res-hdr="+ str(req_hdr_len)+", res-body=" + str(res_hdr_len)

        return headers, http_message, body

    def _build_url_message(self, path, parsed):
        # Construct HTTP message for URL-only requests
        http_message = (
            "GET " + path + " HTTP/1.1\r\n"
            "Host: " + parsed.hostname + "\r\n"
            'User-Agent: IcapClient/1.0\r\n'
            'Accept: */*\r\n'
            'Connection: close\r\n'
            '\r\n'
        )
        return http_message

    def _build_content_message(self, req_method, path, parsed, content):
        # Construct HTTP message for content uploads
        http_message = (
            req_method + " " + path +" HTTP/1.1\r\n"
            "Host: " + (parsed.hostname or "localhost") +"\r\n"
            "Content-Length: "+ str(len(content)) +"\r\n"
            'Content-Type: application/octet-stream\r\n'
            'User-Agent: IcapClient/1.0\r\n'
            '\r\n'
        )
        return http_message

    def _build_respmod_message(self, content=None):
        # Construct HTTP response message for RESPMOD requests
        if content is not None:
            status_line = "HTTP/1.1 " + content.status_code + " " +content.reason +"\r\n"
            header_lines = ""
            excluded = {"proxy-connection", "transfer-encoding", "content-encoding"}
            for k, v in content.headers.items():
                if k.lower() not in excluded:
                    header_lines += k+": "+v+"\r\n"
            http_message = status_line + header_lines + "\r\n"
        else:
            # If content came from file, make a synthetic response
            status_line = "HTTP/1.1 200 OK\r\n"
            http_message = status_line + "Content-Type: application/octet-stream\r\n\r\n"
        return http_message
        


def run_cli(args):
    output_path = args.output

    def write_cli_output(text):
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(text)
            print("Response saved to: "+output_path)
        else:
            print(text)

    if not args.server:
        write_cli_output("Error: --server is required")
        return 1
    if args.port is None:
        write_cli_output("Error: --port is required")
        return 1
    if not args.method:
        write_cli_output("Error: --method is required")
        return 1
    if args.timeout is None:
        write_cli_output("Error: --timeout is required")
        return 1
    if args.method != "OPTIONS" and not args.file and not args.url:
        write_cli_output("Error: --file or --url is required")
        return 1

    if args.timeout <= 0:
        write_cli_output("Error: --timeout must be a positive number")
        return 1
    if args.port <= 0:
        write_cli_output("Error: --port must be a positive number")
        return 1

    if args.file and not os.path.isfile(args.file):
        write_cli_output("Error: File '" + args.file +"' does not exist.")
        return 1

    service_path = "/reqmod" if args.method=="REQMOD" else "/respmod"
    content = None
    
    if args.file and args.method != "OPTIONS":
        with open(args.file,"rb") as f:
            content = f.read()

    try:
        icap_client = IcapClient(args.server, args.port, args.tls, args.accept_204, args.ignore_cert_errors, args.enforce_srv_cert, args.preview, args.timeout, args.api_key)
        raw_response = icap_client.adapt_content(content, icap_service=service_path, method=args.method, url=args.url, req_method=args.req_method)
        response = sanitize_response_output(raw_response)
        has_displayable_text = bool(
            response and any(not ch.isspace() for ch in response)
        )
        if has_displayable_text:
            content_to_write = response
        elif raw_response:
            content_to_write = ""
        else:
            content_to_write = "Error: No response received from server."

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content_to_write)
            print("Response saved to: "+output_path)
        else:
            print(content_to_write)
        return 0
    except Exception as e:
        write_cli_output("Error: "+str(e))
        return 1


def main():
    parser = argparse.ArgumentParser(description="ICAP Client - GUI/CLI",formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--cli', '-c',action='store_true', help='Run CLI mode')
    parser.add_argument('--file', '-f', type=str, help='File to send')
    parser.add_argument('--url', '-u', type=str, help='URL to fetch (required if no file)')
    parser.add_argument('--enforce-srv-cert', '-e', action='store_false')
    parser.add_argument('--server', '-s', type=str, default=None)
    parser.add_argument('--port', '-p', type=int, default=1344)
    parser.add_argument('--method', '-m', choices=['REQMOD','RESPMOD', 'OPTIONS'], default='OPTIONS')
    parser.add_argument('--tls', '-t', action='store_true')
    parser.add_argument('--ignore-cert-errors', '-i', action='store_true', help='ignore ICAP server cert errors')
    parser.add_argument('--accept-204', '-a', action='store_true')
    parser.add_argument('--output', '-o', type=str)
    parser.add_argument('--preview', type=int, default=None, help='Number of preview bytes')
    parser.add_argument('--timeout', type=int, default=10, help='Socket timeout in seconds')
    parser.add_argument('--req_method', '-r', choices=['PUT', 'POST'], default='POST')
    parser.add_argument('--api-key', type=str, default=None, help='Optional API key for Authorization header')
    args = parser.parse_args()

    if args.cli:
        return run_cli(args)
    else:
        print("GUI unavailable, use --cli")
        return 1

if __name__=="__main__":
    sys.exit(main())
