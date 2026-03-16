# icap-client-tester

A lightweight ICAP client testing script for validating ICAP servers and services.

## Disclaimer

This tool is not officially supported or maintained by Security and is provided "as is" without warranties or guarantees of any kind. It is designed to be used while validating and testing against ICAP servers and services.

## Quickstart

```bash
pip install requests
python icaptest.0.9.4.py
```

## Dependencies

- Python 3.x
- requests (for RESPMOD URL fetches)
- Tkinter (for GUI mode; usually included with Python)

Install requests if needed:

```bash
pip install requests
```

## GUI Mode

Start the GUI:

```bash
python icaptest.0.9.4.py
```

In the GUI you can:

- Select a file (optional)
- Enter a URL (required if no file)
- Set ICAP server address/port and timeout (default 60 seconds)
- Optionally set an API key for Basic auth (`Authorization: Basic <key>`)
- Toggle TLS/ICAPS and cert handling
- Choose REQMOD/RESPMOD/OPTIONS
- Enable Preview/Early 204
- Send the request and view the response

## CLI

Show CLI help:

```bash
python icaptest.0.9.4.py --help
```

Available CLI switches:

- `--cli`, `-c`: Run in CLI mode
- `--file`, `-f`: File to send
- `--url`, `-u`: URL to fetch (required if no file)
- `--enforce-srv-cert`, `-e`: Disable URL server cert verification for URL fetches
- `--server`, `-s`: ICAP server address (default `192.168.197.126`)
- `--port`, `-p`: ICAP server port (default `1344`)
- `--method`, `-m`: ICAP method: `REQMOD`, `RESPMOD`, `OPTIONS` (default `REQMOD`)
- `--tls`, `-t`: Enable TLS/ICAPS
- `--ignore-cert-errors`, `-i`: Ignore ICAP server cert errors
- `--accept-204`, `-a`: Accept early 204 responses
- `--output`, `-o`: Save response to a file
- `--preview`: Number of preview bytes
- `--timeout`: Socket timeout in seconds (default `60`)
- `--api-key`: Optional API key for `Authorization: Basic` header
- `--req_method`, `-r`: HTTP method for REQMOD content: `PUT` or `POST` (default `POST`)

REQMOD with a file:

```bash
python icaptest.0.9.4.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload
```

REQMOD with URL only:

```bash
python icaptest.0.9.4.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --url http://example.com/
```

RESPMOD (fetches the URL and sends response body):

```bash
python icaptest.0.9.4.py --cli --server 127.0.0.1 --port 1344 \
  --method RESPMOD --url http://example.com/
```

OPTIONS:

```bash
python icaptest.0.9.4.py --cli --server 127.0.0.1 --port 1344 \
  --method OPTIONS --url http://example.com/
```

Set a custom timeout (default 60 seconds):

```bash
python icaptest.0.9.4.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --timeout 30
```

TLS (ICAPS) with optional ignore cert errors:

```bash
python icaptest.0.9.4.py --cli --server icap.example.com --port 11344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --tls --ignore-cert-errors
```

Preview + early 204:

```bash
python icaptest.0.9.4.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --accept-204 --preview 1024
```

Save response to a file:

```bash
python icaptest.0.9.4.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --output response.txt
```

REQMOD with API key (Basic auth header):

```bash
python icaptest.0.9.4.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --api-key YOUR_API_KEY_VALUE
```

## Supported ICAP Features

- REQMOD, RESPMOD, and OPTIONS
- TLS/ICAPS
- Preview mode and early 204 handling
- Chunked transfer encoding for request bodies
- URL-based RESPMOD (fetches URL content via requests)
- CLI and GUI modes
- Configurable timeout for socket operations
- Optional Basic auth header via API key in GUI and CLI
