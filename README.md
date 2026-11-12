# PowerDNS DynHost for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/hacs/integration)
![downloads](https://img.shields.io/badge/dynamic/json?color=41BDF5&logo=home-assistant&label=integration%20usage&suffix=%20installs&cacheSeconds=15600&url=https://analytics.home-assistant.io/custom_integrations.json&query=$.pdns.total)

Keep a DNS record on your own [PowerDNS](https://www.powerdns.com/) authoritative server in sync with the public IP address of your Home Assistant host. It works like a dynamic DNS service (DynDNS / DynHost) that you host yourself.

The integration sends standard **DNS dynamic updates (RFC 2136)** signed with a **TSIG key**. It does not use the PowerDNS HTTP API. It can update:

- the **A** record (IPv4),
- the **AAAA** record (IPv6),
- or both.

Every 10 minutes, the integration:

1. detects the public IP address(es) of the Home Assistant host;
2. queries your PowerDNS server directly for the current records;
3. sends an update only for the records that changed.

## Installation

### HACS (recommended)

1. In HACS, add `https://github.com/cyr-ius/hass-pdns` as a custom repository (category: _Integration_).
2. Install **PowerDNS DynHost**, then restart Home Assistant.

### Manual

Copy `custom_components/pdns` into the `custom_components` folder of your Home Assistant configuration, then restart Home Assistant.

## Preparing PowerDNS

Dynamic updates must be enabled and allowed for the zone that contains your record.

1. Enable DNS updates in `pdns.conf`, and allow the IP addresses Home Assistant connects from:

   ```ini
   dnsupdate=yes
   allow-dnsupdate-from=192.0.2.10/32,2001:db8::/64
   ```

2. Create a TSIG key:

   ```sh
   pdnsutil generate-tsig-key home-assistant hmac-sha256
   ```

3. Allow this key to update the zone:

   ```sh
   pdnsutil set-meta example.com TSIG-ALLOW-DNSUPDATE home-assistant
   ```

4. Read the key secret (base64) that you will enter in Home Assistant:

   ```sh
   pdnsutil list-tsig-keys
   ```

PowerDNS 5 also offers new subcommand names (`pdnsutil tsigkey generate`, `pdnsutil metadata set`, …). See the [PowerDNS dynamic DNS update documentation](https://doc.powerdns.com/authoritative/dnsupdate.html) for your version.

The server must be reachable from Home Assistant on **UDP port 53**. It can be reached over IPv4 or IPv6.

## Configuration

Add the integration from the Home Assistant UI:

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=pdns)

| Field                | Description                                                                                        |
| -------------------- | -------------------------------------------------------------------------------------------------- |
| DNS Server           | IP address or hostname of the PowerDNS authoritative server.                                       |
| DNS Alias            | Fully qualified name to update, e.g. `home.example.com`.                                           |
| TSIG Key Name        | Name of the TSIG key, e.g. `home-assistant`.                                                       |
| TSIG Key Secret      | Base64 secret of the TSIG key.                                                                     |
| Algorithm            | TSIG algorithm: `hmac-sha256` (default), `hmac-sha512`, `hmac-sha384` or `hmac-sha224`.            |
| TTL                  | TTL of the record, in seconds (default: `300`).                                                    |
| IP version to update | IPv4 only (A), IPv6 only (AAAA), or IPv4 and IPv6 (A + AAAA). Default for new installations: both. |

The zone to update is **detected on the server** (SOA lookup): it is the zone hosted by the server that contains the alias. For example, `home.example.com` and `a.b.example.com` are both updated in the zone `example.com` if that is the zone the server hosts. If the server hosts no zone containing the alias, the form shows an error. A typo can still match another zone hosted by the server, so double-check the alias.

A first update runs when you submit the form. The entry is created only if this update succeeds.

### IPv4 and IPv6

When **IPv4 and IPv6** is selected, each address is detected separately and a status screen is shown:

- **Both addresses detected**: the first update is done and both addresses are shown. Confirm, or go back to the form.
- **One address not detected**: nothing is updated. The screen shows which address failed and why. You can switch to the address that works (IPv4 only or IPv6 only), or go back to the form.

### Options

Use **Configure** on the integration to change the IP version later, without removing the entry. The same checks run, including the IPv4 / IPv6 status screen.

Entries created before IPv6 support keep updating the A record only, until you change this option.

## Entity

Each entry creates a **binary sensor** with the _problem_ device class. It turns **on** when the last update failed: public IP not detected, server unreachable, TSIG authentication refused, or timeout.

| Attribute     | Description                                                                         |
| ------------- | ----------------------------------------------------------------------------------- |
| `state`       | `good <addresses>` if a record was updated, `nochg <addresses>` if nothing changed. |
| `public_ip`   | Detected public IPv4 address, if IPv4 is enabled.                                   |
| `public_ipv6` | Detected public IPv6 address, if IPv6 is enabled.                                   |
| `last_seen`   | Date and time of the last successful check.                                         |

## How the public IP is detected

The public addresses are read from [`https://4.ident.me/`](https://4.ident.me/) (IPv4) and [`https://6.ident.me/`](https://6.ident.me/) (IPv6). Only global (public) addresses are accepted.

The request is made from the Home Assistant host. The IPv6 address is therefore the host's own address, which is usually what you want for IPv6, since there is no NAT.

## Troubleshooting

| Error                                                  | Likely cause                                                                                                          |
| ------------------------------------------------------ | --------------------------------------------------------------------------------------------------------------------- |
| Unable to determine public IP address                  | No Internet access, no IPv6 connectivity, or `ident.me` unreachable.                                                  |
| Cannot connect to server or TSIG authentication failed | Wrong server, UDP 53 blocked, wrong key name/secret/algorithm, key not allowed on the zone, or source IP not allowed. |
| The DNS server hosts no zone containing this alias     | Typo in the alias, or wrong server.                                                                                   |
| Connection timeout                                     | Server or `ident.me` not answering within 10 seconds.                                                                 |

When the server refuses an update, the log gives the DNS response code, the server address, the source address and the likely cause. Behind NAT, the source address is the local one, and the log also shows the public address the server actually sees: this is the address to allow in `allow-dnsupdate-from`.

To get more details, enable debug logs:

```yaml
logger:
  logs:
    custom_components.pdns: debug
```

## Credits

Originally based on the official [No-IP.com](https://github.com/home-assistant/core/tree/dev/homeassistant/components/no_ip) and [Mythic Beasts](https://github.com/home-assistant/core/tree/dev/homeassistant/components/mythicbeastsdns) integrations. Thanks to their authors!
