# QUIC sniffer test corpus

The `quic-*.bin` files are client Initial datagrams captured by the Hysteria
project and copied unchanged from
[`apernet/hysteria` `app/v2.13.0`](https://github.com/apernet/hysteria/tree/app/v2.13.0/extras/sniff/testdata),
introduced in commit `4849cda3` ("feat(sniff): rework sniffing to handle
multi-packet QUIC ClientHellos", #1693). Their git blob hashes match that tag.
Hysteria is distributed under the MIT License; its copyright and permission
notice is preserved in [`LICENSE-MIT`](LICENSE-MIT).

Each file holds one UDP datagram. Files sharing a prefix belong to one QUIC
connection and are numbered in the order the client sent them:

| Prefix | Client | Server name |
| --- | --- | --- |
| `quic-chrome153` | Chrome 153; the ClientHello is shuffled across datagrams 0 and 1, and datagram 2 retransmits the fragments of datagram 0 split differently | `chrome.sniff.test` |
| `quic-firefox153esr` | Firefox 153 ESR; each datagram pads with zero bytes after its Initial packet | `firefox.sniff.test` |
| `quic-curl8.14-openssl3.5` | curl 8.14 with OpenSSL 3.5 | `curl.sniff.test` |
| `quic-quiche` | quiche; datagram 1 retransmits datagram 0, and datagram 2 completes the ClientHello and pads with zero bytes | `quiche.sniff.test` |
| `quic-ngtcp2-1.11` | ngtcp2 1.11; one datagram | `ngtcp2.sniff.test` |
| `quic-aioquic1.2` | aioquic 1.2; one datagram padded with zero bytes | `aioquic.sniff.test` |
