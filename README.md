# PowerDNS DynHost Updater Component for Home Assistant

[![hacs_badge](https://img.shields.io/badge/HACS-Custom-orange.svg)](https://github.com/custom-components/hacs)
![downloads](https://img.shields.io/badge/dynamic/json?color=41BDF5&logo=home-assistant&label=integration%20usage&suffix=%20installs&cacheSeconds=15600&url=https://analytics.home-assistant.io/custom_integrations.json&query=$.pdns.total)


With the `pdns` integration you can keep your current IP address in sync with yourhostname or domain.

To use the integration in your installation, add the following to your `configuration.yaml` file:

#### Configuration variables:

| Variable        | Required | Type   | Description                                                 |
| --------------- | -------- | ------ | ----------------------------------------------------------- |
| `domain`        | yes      | string | The subdomain you are modifying the DNS configuration for   |
| `username`      | yes      | string | The DynHost username                                        |
| `password`      | yes      | string | Password for the DynHost username                           |
| `url`           | yes      | string | Url for the DynHost server                                  |
| `scan_interval` | no       | time   | How often to call the update service. (default: 10 minutes) |

#### Basic Example:

```yaml
pdns:
  domain: subdomain.domain.com
  username: YOUR_USERNAME
  password: YOUR_PASSWORD
  url: http://xxxxx
```

Based on the official [No-IP.com](https://github.com/home-assistant/core/tree/dev/homeassistant/components/no_ip) and [Mythic Beasts](https://github.com/home-assistant/core/blob/dev/homeassistant/components/mythicbeastsdns) integrations. Thanks to the creators!

## Configuration

The preferred way to setup the platform is by enabling the discovery component.
Add your equipment via the Integration menu

[![Open your Home Assistant instance and start setting up a new integration.](https://my.home-assistant.io/badges/config_flow_start.svg)](https://my.home-assistant.io/redirect/config_flow_start/?domain=pdns)
