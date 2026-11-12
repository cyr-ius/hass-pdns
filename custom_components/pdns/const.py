"""Constants for PDNS."""

DOMAIN = "pdns"
CONF_PDNSSRV = "pdns_server"
CONF_ALIAS = "dns_alias"
CONF_TSIG_ALGORITHM = "tsig_algorithm"
CONF_TTL = "ttl"
CONF_IP_VERSION = "ip_version"
PLATFORMS = ["binary_sensor"]

TSIG_ALGORITHMS = [
    "hmac-sha256",
    "hmac-sha512",
    "hmac-sha384",
    "hmac-sha224",
]
DEFAULT_TTL = 300
DEFAULT_ALGORITHM = "hmac-sha256"

IP_VERSION_V4 = "ipv4"
IP_VERSION_V6 = "ipv6"
IP_VERSION_BOTH = "both"
IP_VERSIONS = [IP_VERSION_V4, IP_VERSION_V6, IP_VERSION_BOTH]
# Proposed for new installations
DEFAULT_IP_VERSION = IP_VERSION_BOTH
# Entries created before IPv6 support only updated the A record
LEGACY_IP_VERSION = IP_VERSION_V4
