"""PDNS Api."""

import asyncio
import ipaddress
import logging
import socket
from datetime import datetime
from typing import Any

import dns.exception
import dns.name
import dns.query
import dns.rcode
import dns.resolver
import dns.tsigkeyring
import dns.update
from aiohttp import ClientError, ClientSession, ClientTimeout

from .const import IP_VERSION_BOTH, IP_VERSION_V4, IP_VERSION_V6

MYIP_CHECK_V4 = "https://4.ident.me/"
MYIP_CHECK_V6 = "https://6.ident.me/"
MYIP_TIMEOUT = ClientTimeout(total=10)
MYIP_MAX_BYTES = 64

# Record type -> (public IP lookup URL, address class)
RECORD_TYPES: dict[
    str, tuple[str, type[ipaddress.IPv4Address] | type[ipaddress.IPv6Address]]
] = {
    "A": (MYIP_CHECK_V4, ipaddress.IPv4Address),
    "AAAA": (MYIP_CHECK_V6, ipaddress.IPv6Address),
}

IP_VERSION_RECORDS = {
    IP_VERSION_V4: ("A",),
    IP_VERSION_V6: ("AAAA",),
    IP_VERSION_BOTH: ("A", "AAAA"),
}

_LOGGER = logging.getLogger(__name__)


class PDNS:
    """PowerDNS update via DNS Dynamic Update (RFC 2136) with TSIG authentication.

    username = TSIG key name
    password = TSIG key secret (base64)
    """

    def __init__(
        self,
        servername: str,
        alias: str,
        username: str,
        password: str,
        algorithm: str = "hmac-sha256",
        ttl: int = 300,
        session: ClientSession | None = None,
        ip_version: str = IP_VERSION_V4,
    ) -> None:
        """Initialize."""
        self.server = servername
        alias_name = dns.name.from_text(alias)
        self.alias = alias_name
        self.zone = alias_name.parent()
        self.algorithm = algorithm
        self.ttl = ttl
        self.session = session if session else ClientSession()
        if ip_version not in IP_VERSION_RECORDS:
            raise ValueError(f"Unsupported IP version: {ip_version}")
        self.record_types = IP_VERSION_RECORDS[ip_version]
        self._key_name = dns.name.from_text(username)
        # TSIG keys from BIND/PowerDNS often lack base64 padding
        padded_secret = password + "=" * (-len(password) % 4)
        self._keyring = dns.tsigkeyring.from_text({username: padded_secret})

    async def async_update(self) -> dict[str, Any]:
        """Update DNS records via RFC 2136 dynamic update with TSIG."""
        public_ips = {
            rdtype: await self._async_get_public_ip(rdtype)
            for rdtype in self.record_types
        }
        updated = await asyncio.get_running_loop().run_in_executor(
            None, self._do_dns_update, public_ips
        )
        for rdtype, ip in public_ips.items():
            if rdtype in updated:
                _LOGGER.debug(
                    "TSIG update: %s %s -> %s (zone: %s)",
                    self.alias,
                    rdtype,
                    ip,
                    self.zone,
                )
            else:
                _LOGGER.debug(
                    "TSIG no change: %s %s already points to %s",
                    self.alias,
                    rdtype,
                    ip,
                )

        addresses = " ".join(public_ips.values())
        return {
            "state": f"good {addresses}" if updated else f"nochg {addresses}",
            "public_ip": public_ips.get("A"),
            "public_ipv6": public_ips.get("AAAA"),
            "last_seen": datetime.now(),
        }

    async def async_detect_public_ips(self) -> dict[str, str | PDNSFailed]:
        """Detect each public IP independently, without updating DNS.

        Returns the address, or the detection error, for each record type.
        """
        results: dict[str, str | PDNSFailed] = {}
        for rdtype in self.record_types:
            try:
                results[rdtype] = await self._async_get_public_ip(rdtype)
            except PDNSFailed as error:
                results[rdtype] = error
        return results

    async def _async_get_public_ip(self, rdtype: str) -> str:
        """Get and validate the public IP address for a record type (A or AAAA)."""
        url, address_class = RECORD_TYPES[rdtype]
        try:
            async with self.session.get(url, timeout=MYIP_TIMEOUT) as response:
                if response.status != 200:
                    raise DetectionFailed(
                        f"Can't fetch public {rdtype} ip ({response.status})"
                    )
                raw = b""
                while chunk := await response.content.read(MYIP_MAX_BYTES):
                    raw += chunk
                    if len(raw) > MYIP_MAX_BYTES:
                        raise DetectionFailed("Public IP response too large")
        except TimeoutError as error:
            raise TimeoutExpired(
                f"Timeout to get public {rdtype} ip address"
            ) from error
        except ClientError as error:
            raise DetectionFailed(str(error)) from error

        try:
            address = address_class(raw.decode("ascii").strip())
        except (UnicodeDecodeError, ValueError) as error:
            raise DetectionFailed(
                f"Invalid public {rdtype} IP address received"
            ) from error
        if not address.is_global:
            raise DetectionFailed(f"Public IP address is not global: {address}")

        public_ip = str(address)
        _LOGGER.debug("Public IP (%s): %s", rdtype, public_ip)
        return public_ip

    def _resolve_server(self) -> str:
        """Resolve the DNS server address (IPv4 or IPv6)."""
        infos = socket.getaddrinfo(
            self.server, 53, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP
        )
        if not infos:
            raise CannotConnect(f"Unable to resolve {self.server}")
        return str(infos[0][4][0])

    def _do_dns_update(self, public_ips: dict[str, str]) -> set[str]:
        """Update only the records that changed. Returns the updated record types."""
        try:
            server_ip = self._resolve_server()

            # Query the authoritative server directly to avoid cache
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [server_ip]

            to_update: dict[str, str] = {}
            for rdtype, ip in public_ips.items():
                try:
                    answers = resolver.resolve(self.alias, rdtype)
                    current = {ipaddress.ip_address(rdata.address) for rdata in answers}
                    if current == {ipaddress.ip_address(ip)}:
                        continue
                except dns.exception.DNSException:
                    pass  # record missing or unresolvable — proceed with update
                to_update[rdtype] = ip

            if not to_update:
                return set()

            update = dns.update.Update(
                self.zone,
                keyring=self._keyring,
                keyname=self._key_name,
                keyalgorithm=self.algorithm,
            )
            for rdtype, ip in to_update.items():
                update.replace(self.alias, self.ttl, rdtype, ip)
            response = dns.query.udp(update, server_ip, timeout=10)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                raise CannotConnect(f"DNS update failed: {dns.rcode.to_text(rcode)}")
            return set(to_update)
        except dns.exception.Timeout as error:
            raise TimeoutExpired(f"DNS update timeout for {self.alias}") from error
        except dns.exception.DNSException as error:
            raise CannotConnect(str(error)) from error
        except OSError as error:
            raise CannotConnect(str(error)) from error


class PDNSFailed(Exception):
    """Error to indicate there is invalid pdns communication."""


class DetectionFailed(PDNSFailed):
    """Error to indicate public IP retrieval failed."""


class CannotConnect(PDNSFailed):
    """Error to indicate we cannot connect."""


class TimeoutExpired(PDNSFailed):
    """Error to indicate a timeout occurred."""
