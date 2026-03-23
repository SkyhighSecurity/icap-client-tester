import tkinter as tk
from tkinter import filedialog, messagebox
import socket
import ssl
import os
import argparse
import sys
import re
import threading
from urllib.parse import urlparse
import requests

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
    if response is None:
        return None
    if not isinstance(response, str):
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
                    return f'TLS Connection failed: {str(e)}'

            if self.preview is not None and icap_method != 'OPTIONS':
                headers['Preview'] = str(self.preview)

            request_line = f"{icap_method} icap://{self.server_address}{icap_service} ICAP/1.0\r\n"
            header_lines = "\r\n".join([f"{k}: {v}" for k, v in headers.items()])

            s.sendall(f"{request_line}{header_lines}\r\n\r\n".encode())

            http_request and s.sendall(http_request.encode())

            response = self._send_chunked_body(s, body) if body else self._receive_response(s)

            s.close()
            return response

        except socket.timeout:
            return f"Connection timed out after {self.timeout} seconds to {self.server_address}:{self.server_port}"
        except ConnectionRefusedError:
            return f"Connection refused by {self.server_address}:{self.server_port}"
        except Exception as e:
            print(f"Error sending request: {e}")
            return f"Error sending request: {e}"

    def _send_chunked_body(self, s, body):
        def send_chunks(sock, data, chunk_size=1024):
            """Send data in ICAP chunked-encoding format."""
            remaining = data
            while remaining:
                chunk = remaining[:chunk_size]
                remaining = remaining[chunk_size:]
                sock.sendall(f"{len(chunk):X}\r\n".encode())
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
                print(sanitize_response_output(response))
                if not response.startswith("ICAP/1.0 100"):
                    return response

                # send full body after continue
                send_chunks(s, body)

            # ---------------- preview > 0 ----------------
            else:
                preview_chunk = body[:self.preview]

                # send preview
                s.sendall(f"{len(preview_chunk):X}\r\n".encode())
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
            print(f"Error receiving response: {e}")
            if not data:
                return f"Error receiving response: {e}"
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
            headers['Authorization'] = f'Basic {self.api_key}'
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
        path += f'?{parsed.query}' if parsed.query else ''

        if content:
            http_message = self._build_content_message(req_method, path, parsed, content)
            headers['Encapsulated'] = f'req-hdr=0, req-body={len(http_message)}'
        else:
            http_message = self._build_url_message(path, parsed)
            headers['Encapsulated'] = f'req-hdr=0, null-body={len(http_message)}'

        return headers, http_message

    def _handle_respmod(self, content, url, headers):
        if not url:
            raise ValueError('RESPMOD requires a URL')

        parsed = urlparse(url)
        path = f"{parsed.path or '/'}{f'?{parsed.query}' if parsed.query else ''}"

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

        headers['Encapsulated'] = f'req-hdr=0, res-hdr={req_hdr_len}, res-body={res_hdr_len}'

        return headers, http_message, body

    def _build_url_message(self, path, parsed):
        # Construct HTTP message for URL-only requests
        http_message = (
            f'GET {path} HTTP/1.1\r\n'
            f'Host: {parsed.hostname}\r\n'
            'User-Agent: IcapClient/1.0\r\n'
            'Accept: */*\r\n'
            'Connection: close\r\n'
            '\r\n'
        )
        return http_message

    def _build_content_message(self, req_method, path, parsed, content):
        # Construct HTTP message for content uploads
        http_message = (
            f'{req_method} {path} HTTP/1.1\r\n'
            f'Host: {parsed.hostname or "localhost"}\r\n'
            f'Content-Length: {len(content)}\r\n'
            'Content-Type: application/octet-stream\r\n'
            'User-Agent: IcapClient/1.0\r\n'
            '\r\n'
        )
        return http_message

    def _build_respmod_message(self, content=None):
        # Construct HTTP response message for RESPMOD requests
        if content is not None:
            status_line = f"HTTP/1.1 {content.status_code} {content.reason}\r\n"
            header_lines = ""
            excluded = {"proxy-connection", "transfer-encoding", "content-encoding"}
            for k, v in content.headers.items():
                if k.lower() not in excluded:
                    header_lines += f"{k}: {v}\r\n"
            http_message = status_line + header_lines + "\r\n"
        else:
            # If content came from file, make a synthetic response
            status_line = "HTTP/1.1 200 OK\r\n"
            http_message = status_line + f"Content-Type: application/octet-stream\r\n\r\n"
        return http_message
        

class IcapGuiApp:

    def toggle_preview(self):
        if self.preview_on_var.get():
            self.preview_entry.config(state='normal')
        else:
            self.preview_entry.config(state='disabled')

    def toggle_reqmethod(self):
        if self.method_var.get() == 'REQMOD' and self.file_path.get():
            self.req_method_checkbox.config(state='normal')
        else:
            self.req_method_checkbox.config(state='disabled')
            self.req_method_var.set(False)

    def toggle_srvcert(self):
        if self.method_var.get() == 'RESPMOD':
            self.enforce_srv_cert_checkbox.config(state='normal')
        else:
            self.enforce_srv_cert_checkbox.config(state='disabled')
            
    def toggle_tls(self):
        if self.tls_var.get():
            self.server_port_var.set("11344")
        else:
            self.server_port_var.set("1344")

    def validate_preview_entry(self, *args):
        value = self.preview_entry.get()
        if value == '':
            messagebox.showwarning("Warning", "Preview bytes cannot be blank")
            self.preview_var.set(0)
            return
        try:
            preview_bytes = int(value)
            if preview_bytes < 0:
                messagebox.showwarning("Warning", "Preview bytes must be positive")
                self.preview_var.set(0)            
        except ValueError:
            messagebox.showwarning("Warning", "Preview bytes must be a number")
            self.preview_var.set(0)

    def __init__(self, root):
        self.root = root
        self.root.title("ICAP Client 0.9.5")

        self.icap_client = None

        # File Selection
        tk.Label(root, text="Select File (optional):").grid(row=0, column=0, padx=10, pady=5, sticky='w')
        self.file_path = tk.StringVar()
        file_frame = tk.Frame(root)
        file_frame.grid(row=0, column=1, padx=10, pady=5, sticky='w')
        self.file_entry = tk.Entry(file_frame, textvariable=self.file_path, width=50)
        self.file_entry.pack(side='left')
        tk.Button(file_frame, text="Browse", command=self.browse_file).pack(side='left', padx=(10,0))
        self.file_path.trace_add('write', lambda *args: self.toggle_reqmethod())

        # URL input
        tk.Label(root, text="Full URL with scheme (required if no file):").grid(row=1, column=0, padx=10, pady=10, sticky='w')
        self.url_var = tk.StringVar(value="")
        tk.Entry(root, textvariable=self.url_var, width=50).grid(row=1, column=1, padx=10, pady=10, sticky='w')

        # ICAP server
        self.server_address_var = tk.StringVar(value="<FQDN or IP>")
        self.server_port_var = tk.StringVar(value="1344")
        tk.Label(root, text="ICAP Server Address or FQDN:").grid(row=3, column=0, padx=10, pady=10, sticky='w')
        tk.Entry(root, textvariable=self.server_address_var, width=15).grid(row=3, column=1, padx=10, pady=10, sticky='w')
        tk.Label(root, text="Port:").grid(row=3, column=1, padx=150, pady=10, sticky='w')
        tk.Entry(root, textvariable=self.server_port_var, width=5).grid(row=3, column=1, padx=180, pady=10, sticky='w')

        # Timeout
        self.timeout_var = tk.StringVar(value="10")
        tk.Label(root, text="Timeout (sec):").grid(row=4, column=0, padx=10, pady=3, sticky='w')
        tk.Entry(root, textvariable=self.timeout_var, width=6).grid(row=4, column=1, padx=10, pady=3, sticky='w')
        self.api_key_var = tk.StringVar(value="")
        tk.Label(root, text="API Key (optional):").grid(row=4, column=1, padx=90, pady=3, sticky='w')
        tk.Entry(root, textvariable=self.api_key_var, width=35, show="*").grid(row=4, column=1, padx=210, pady=3, sticky='w')

        # TLS Encryption options
        tk.Label(root, text="Encryption:").grid(row=5, column=0, padx=10, pady=3, sticky='w')
        self.tls_var = tk.BooleanVar(value=False)
        tk.Checkbutton(root, text="Use TLS (ICAPS)", variable=self.tls_var).grid(row=5, column=1, padx=5, pady=3, sticky='w')
        self.ignore_cert_var = tk.BooleanVar(value=False)
        tk.Checkbutton(root, text="Ignore ICAP Server Certificate Errors", variable=self.ignore_cert_var).grid(row=5, column=1, padx=150, pady=3, sticky='w')
        self.tls_var.trace_add('write', lambda *args: self.toggle_tls())

        # Method
        self.method_var = tk.StringVar(value="OPTIONS")
        self.req_method_var = tk.BooleanVar(value=False)
        tk.Label(root, text="ICAP Method:").grid(row=6, column=0, padx=10, pady=10, sticky='w')
        tk.OptionMenu(root, self.method_var, "REQMOD", "RESPMOD", "OPTIONS").grid(row=6, column=1, padx=5, pady=2, sticky='w')
        self.req_method_checkbox = tk.Checkbutton(root, text="Use PUT instead of POST", variable=self.req_method_var)
        self.req_method_checkbox.grid(row=6, column=1, padx=150, pady=3, sticky='w')
        self.method_var.trace_add('write', lambda *args: self.toggle_reqmethod())
        self.toggle_reqmethod()      

        # Enforce server cert errors
        self.enforce_srv_cert_var = tk.BooleanVar(value=False)
        self.enforce_srv_cert_checkbox = tk.Checkbutton(root, text="Enforce URL Server Certificate Errors", variable=self.enforce_srv_cert_var)
        self.enforce_srv_cert_checkbox.grid(row=7, column=1, padx=5, pady=2, sticky='w')
        self.method_var.trace_add('write', lambda *args: self.toggle_srvcert())
        self.toggle_srvcert()
              
        # Early 204 and Preview
        self.preview_on_var = tk.BooleanVar(value=False)
        tk.Checkbutton(root, text="Accept Early 204 and Enable Preview", variable=self.preview_on_var, command=self.toggle_preview).grid(row=8, column=1, padx=5, pady=2, sticky='w')

        # Preview bytes Frame
        preview_frame = tk.Frame(root)
        self.preview_var = tk.IntVar(value=0)
        self.preview_entry = tk.Entry(preview_frame, textvariable=self.preview_var, width=4)
        self.preview_entry.pack(side="left")
        label = tk.Label(preview_frame, text=" Preview Byte Count (Use OPTIONS to get server max)")
        label.pack(side="left")
        self.preview_var.trace_add('write', self.validate_preview_entry)

        # Place the frame in column 1
        preview_frame.grid(row=10, column=1, padx=10, pady=10, sticky="w")

        # Initial state
        self.preview_entry.config(state='disabled')

        # Place the frame in column 1
        preview_frame.grid(row=10, column=1, padx=10, pady=10, sticky="w")

        # Send button
        self.send_button = tk.Button(root, text="Send Request", command=self.send_request, bg='lightblue')
        self.send_button.grid(row=11, column=1, padx=5, pady=10, sticky="w")
        self.status_var = tk.StringVar(value="Ready")
        tk.Label(root, textvariable=self.status_var).grid(row=11, column=1, padx=120, pady=10, sticky="w")

        # Response display
        tk.Label(root, text="ICAP Server Response:").grid(row=12, column=0, padx=10, pady=10, sticky='nw')
        response_frame = tk.Frame(root)
        response_frame.grid(row=12, column=0, columnspan=2, padx=(150,10), pady=10, sticky='ew')
        self.response_text = tk.Text(response_frame, height=15, width=60, wrap=tk.WORD)
        scrollbar = tk.Scrollbar(response_frame, orient=tk.VERTICAL, command=self.response_text.yview)
        self.response_text.configure(yscrollcommand=scrollbar.set)
        self.response_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        root.columnconfigure(1, weight=1)
        root.rowconfigure(12, weight=1)

    def browse_file(self):
        file_path = filedialog.askopenfilename(title="Select a file")
        if file_path:
            self.file_path.set(file_path)

    def send_request(self):
        file_path = self.file_path.get()
        url = self.url_var.get().strip()
        enforce_srv_cert = self.enforce_srv_cert_var.get()
        server_address = self.server_address_var.get().strip()
        server_port_raw = self.server_port_var.get().strip()
        timeout_raw = self.timeout_var.get().strip()
        api_key = self.api_key_var.get().strip()
        method = self.method_var.get().strip()

        if not method:
            messagebox.showerror("Error", "Please select an ICAP method")
            return
        if not server_address or server_address == "<FQDN or IP>":
            messagebox.showerror("Error", "ICAP server address/FQDN is required")
            return
        if not server_port_raw:
            messagebox.showerror("Error", "ICAP port is required")
            return
        if not timeout_raw:
            messagebox.showerror("Error", "Timeout is required")
            return
        try:
            server_port = int(server_port_raw)
            timeout = int(timeout_raw)
        except ValueError:
            messagebox.showerror("Error", "Port and timeout must be numeric values")
            return

        service_path = "/reqmod" if method == "REQMOD" else "/respmod"
        req_method = "PUT" if self.req_method_var.get() else "POST"

        use_tls = self.tls_var.get()
        ignore_cert_errors = self.ignore_cert_var.get() if use_tls else None       

        if self.preview_on_var.get() == True:
            preview = self.preview_var.get()
            accept_early_204 = True
        else:
            preview = None
            accept_early_204 = None

        content = None
        if file_path and os.path.isfile(file_path) and method != "OPTIONS":
            with open(file_path, "rb") as f:
                content = f.read()

        if not content and not url and not method == "OPTIONS":
            messagebox.showerror("Error", "Please provide a file or a URL")
            return

        if server_port <= 0:
            messagebox.showerror("Error", "Port must be a positive number")
            return
        if timeout <= 0:
            messagebox.showerror("Error", "Timeout must be a positive number")
            return

        self.send_button.config(state='disabled')
        self.status_var.set("Sending request...")
        self.response_text.delete(1.0, tk.END)
        self.response_text.insert(tk.END, "Request in progress...\n")

        thread = threading.Thread(
            target=self._send_request_worker,
            args=(
                server_address,
                server_port,
                use_tls,
                accept_early_204,
                ignore_cert_errors,
                enforce_srv_cert,
                preview,
                timeout,
                api_key,
                content,
                service_path,
                method,
                url,
                req_method,
            ),
            daemon=True,
        )
        thread.start()

    def _send_request_worker(
        self,
        server_address,
        server_port,
        use_tls,
        accept_early_204,
        ignore_cert_errors,
        enforce_srv_cert,
        preview,
        timeout,
        api_key,
        content,
        service_path,
        method,
        url,
        req_method,
    ):
        try:
            self.icap_client = IcapClient(
                server_address,
                server_port,
                use_tls,
                accept_early_204,
                ignore_cert_errors,
                enforce_srv_cert,
                preview,
                timeout,
                api_key,
            )
            response = self.icap_client.adapt_content(
                content,
                icap_service=service_path,
                method=method,
                url=url,
                req_method=req_method,
            )
            sanitized_response = sanitize_response_output(response)
            self.root.after(0, lambda: self._on_request_done(sanitized_response))
        except Exception as e:
            self.root.after(0, lambda: self._on_request_done(f"Failed to send request: {e}"))

    def _on_request_done(self, response):
        self.send_button.config(state='normal')
        self.status_var.set("Ready")
        self.response_text.delete(1.0, tk.END)
        if response:
            self.response_text.insert(tk.END, response)
        else:
            self.response_text.insert(tk.END, "Error: No response received from server. Please check server address, port, and certificate status")


def run_cli(args):
    output_path = args.output

    def write_cli_output(text):
        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(text)
            print(f"Response saved to: {output_path}")
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
        write_cli_output(f"Error: File '{args.file}' does not exist.")
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
            response and any(ch.isprintable() and not ch.isspace() for ch in response)
        )
        if has_displayable_text:
            content_to_write = response
        elif raw_response:
            content_to_write = "[response received but content was fully filtered or non-displayable]"
        else:
            content_to_write = "Error: No response received from server."

        if output_path:
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content_to_write)
            print(f"Response saved to: {output_path}")
        else:
            print(content_to_write)
        return 0
    except Exception as e:
        write_cli_output(f"Error: {e}")
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
        try:
            root = tk.Tk()
            app = IcapGuiApp(root)
            root.mainloop()
            return 0
        except tk.TclError:
            print("GUI unavailable, use --cli")
            return 1

if __name__=="__main__":
    sys.exit(main())
