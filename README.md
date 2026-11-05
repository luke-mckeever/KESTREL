# KESTREL

KESTREL is a cyber threat intelligence dashboard that runs locally in your browser. It shows live threat data from free public sources on a world map, along with panels and charts for vulnerabilities, ransomware, attacks, outages and security news.

No API keys are needed to get started.

## Features

- **Map view:** a greyscale world map with live threat layers, animated attack paths from top scanning sources to your location, ransomware campaign trails between each group's victims, and day and night shading.
- **Analytics view:** the threat radar and an industry watch (which sectors are being hit, by whom, and the news behind it) at the top, then a threat timeline of CVEs, KEV additions, ransomware victims and advisories, a vulnerability pressure board ranked by EPSS score, an actor and campaign graph, a sector heatmap, cloud and SaaS outages, and charts for ports, outages and weaknesses.
- **MITRE ATT&CK view:** the ATT&CK matrix with a rotating technique spotlight, plus kill-chain activity, trending techniques, actors and tagged reports.
- **Page presets:** buttons in the top bar for Map, Analytics, MITRE, Ransomware, Vulnerabilities, Network and Outages. The extra presets open on the analytics screen (for example `http://127.0.0.1:8788/#ransom`), each keeps its own layout, and **Cycle** can rotate through them for a wall screen (set the interval under Customise).

## Screenshots

**Map view**

![Map view](docs/screenshot.jpg)

**Analytics view**

![Analytics view](docs/screenshot-analytics.jpg)

## Requirements

- Python 3.7 or newer
- A modern web browser

There are no packages to install.

## Getting started

```bash
git clone https://github.com/<your-username>/KESTREL.git
cd KESTREL
python kestrel.py
```

The dashboard opens in your browser:

- Map view: http://127.0.0.1:8787
- Analytics view: http://127.0.0.1:8788
- MITRE ATT&CK view: http://127.0.0.1:8789

Press `Ctrl+C` in the terminal to stop it.

On Windows, you can also use `start.bat` to start the dashboard and `stop.bat` to stop it.

The first start can take a minute while data loads. After that, data is cached and loads faster.

## Options

```bash
python kestrel.py --port 9000 --analytics-port 9001   # change the ports
python kestrel.py --analytics-port 0                  # map view only
python kestrel.py --no-browser                        # don't open the browser
```

## Optional API keys

Some extra panels need a free API key. To add keys, copy `config.example.json` to `config.json` and fill in your keys, or set them as environment variables. Then restart the dashboard.

| Setting | Environment variable | Purpose |
| --- | --- | --- |
| `abusech_auth_key` | `ABUSECH_AUTH_KEY` | ThreatFox and URLhaus panels |
| `nvd_api_key` | `NVD_API_KEY` | Higher rate limits for CVE data |
| `greynoise_api_key` | `GREYNOISE_API_KEY` | Higher rate limits for IP lookups |

`config.json` is ignored by git, so your keys are not committed.

## Data sources

KESTREL uses public data from sources including CISA, NIST NVD, abuse.ch, SANS ISC, ransomware.live, FIRST.org EPSS, OpenPhish, the Tor Project, IODA and TeleGeography, plus a selection of security news feeds.

Actor, sector and ATT&CK technique matches are found by keyword matching in news and advisory text, so treat them as leads. The data is for general awareness only. Verify any information before acting on it.

## Project structure

```
kestrel.py            Backend server
config.example.json   Template for optional API keys
data/                 Country reference data
static/               Dashboard pages, scripts and styles
docs/                 Screenshots
start.bat, stop.bat   Windows start and stop scripts
```
