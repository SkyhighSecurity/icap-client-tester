# icap-client-tester

A lightweight ICAP client testing script for validating ICAP servers and services.

## Quickstart

```bash
pip install requests
python icaptest.0.9.3.py
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
python icaptest.0.9.3.py
```

In the GUI you can:

- Select a file (optional)
- Enter a URL (required if no file)
- Set ICAP server address/port and timeout (default 10 seconds)
- Toggle TLS/ICAPS and cert handling
- Choose REQMOD/RESPMOD/OPTIONS
- Enable Preview/Early 204
- Send the request and view the response

## CLI

REQMOD with a file:

```bash
python icaptest.0.9.3.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload
```

REQMOD with URL only:

```bash
python icaptest.0.9.3.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --url http://example.com/
```

RESPMOD (fetches the URL and sends response body):

```bash
python icaptest.0.9.3.py --cli --server 127.0.0.1 --port 1344 \
  --method RESPMOD --url http://example.com/
```

OPTIONS:

```bash
python icaptest.0.9.3.py --cli --server 127.0.0.1 --port 1344 \
  --method OPTIONS --url http://example.com/
```

Set a custom timeout (default 10 seconds):

```bash
python icaptest.0.9.3.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --timeout 30
```

TLS (ICAPS) with optional ignore cert errors:

```bash
python icaptest.0.9.3.py --cli --server icap.example.com --port 11344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --tls --ignore-cert-errors
```

Preview + early 204:

```bash
python icaptest.0.9.3.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --accept-204 --preview 1024
```

Save response to a file:

```bash
python icaptest.0.9.3.py --cli --server 127.0.0.1 --port 1344 \
  --method REQMOD --file /path/to/file.bin --url http://example.com/upload \
  --output response.txt
```

## Supported ICAP Features

- REQMOD, RESPMOD, and OPTIONS
- TLS/ICAPS
- Preview mode and early 204 handling
- Chunked transfer encoding for request bodies
- URL-based RESPMOD (fetches URL content via requests)
- CLI and GUI modes
- Configurable timeout for socket operations (Default: 10 seconds)
