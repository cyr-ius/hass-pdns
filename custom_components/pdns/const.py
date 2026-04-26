"""Constants for PDNS."""
DOMAIN = "pdns"
CONF_PDNSSRV = "pdns_server"
CONF_ALIAS = "dns_alias"
CONF_DNS_ZONE = "dns_zone"
CONF_TSIG_ALGORITHM = "tsig_algorithm"
CONF_TTL = "ttl"
PLATFORMS = ["binary_sensor"]

TSIG_ALGORITHMS = [
    "hmac-sha256",
    "hmac-sha512",
    "hmac-sha384",
    "hmac-sha224",
    "hmac-sha1",
    "hmac-md5",
]
DEFAULT_TTL = 300
DEFAULT_ALGORITHM = "hmac-sha256"
