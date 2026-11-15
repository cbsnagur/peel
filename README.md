# Peel

Paste anything a computer handed you. Peel works out what it is and decodes it, layer by layer, entirely in the browser. Nothing is sent anywhere.

Open `index.html` in a browser. It is one self-contained file.

## What it recognizes

- JWTs (claims, expiry; signatures are decoded, not verified)
- JSON, plus repair of broken JSON and Python dicts
- Base64, including gzip or zlib inside
- URLs, query strings, percent-encoding, tracking parameters
- curl commands, converted to JavaScript `fetch` and Python `requests`
- Cron schedules, in English, with the next five runs (assumes a UTC scheduler)
- Unix timestamps and date strings
- Stack traces from JavaScript, Python, Java and Go
- UUIDs, ULIDs, MongoDB ObjectIds, hashes, hex
- Colors with contrast ratios, IPv4 and CIDR blocks, HTTP status codes
- PEM blocks, escaped strings, HTML entities
- Leaked credentials (AWS, GitHub, Stripe, Slack and similar keys)

Nested content is decoded recursively: a curl command opens into its URL, bearer token and JSON body.

## Development

- `engine.js`: detection engine, no DOM, runs in Node and the browser
- `template.html`: page markup, styles and UI code
- `node build.js`: inlines the engine into `index.html`
- `node test.js`: prints engine output for sample inputs
