# Network lists

Snapshots the server reads to classify the address a request comes from (DESIGN.md §81). Refresh them
with `python3 tools/fetch_network_lists.py`; the server re-reads a changed file within a minute. All
three are IPv4 only. First taken 2026-10-15.

| File | Source | Licence |
|---|---|---|
| `x4bnet_vpn_ipv4.txt` | <https://github.com/X4BNet/lists_vpn> — `output/vpn/ipv4.txt`: known VPN providers' networks | MIT, below |
| `x4bnet_datacenter_ipv4.txt` | the same repository — `output/datacenter/ipv4.txt`: VPN and data-centre networks | MIT, below |
| `tor_exits.txt` | The Tor Project's exit list, <https://check.torproject.org/torbulkexitlist> | public data published by the Tor Project |

The X4BNet list's licence covers "the scripts, automation, and the list itself (source files and
generated output)":

```
MIT License

Copyright (c) 2024 X4B (Mathew Heard)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

Its README warns that the data-centre list probably includes your own servers' networks, your DNS
resolvers' and search engines': a source address in it is a measurement, never by itself a reason to
refuse.
