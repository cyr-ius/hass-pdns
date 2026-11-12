"""PDNS Api."""

import asyncio
import ipaddress
import logging
import socket
from datetime import datetime
from typing import Any

import dns.exception
import dns.message
import dns.name
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
DNS_PORT = 53
DNS_TIMEOUT = 10

# Likely cause of a DNS update failure, by rcode
RCODE_HINTS = {
    dns.rcode.REFUSED: (
        "check allow-dnsupdate-from (or ALLOW-DNSUPDATE-FROM) includes the "
        "source address, and TSIG-ALLOW-DNSUPDATE allows the key on the zone"
    ),
    dns.rcode.NOTAUTH: (
        "check the TSIG key name, secret and algorithm, and that the server "
        "is authoritative for the zone"
    ),
    dns.rcode.NOTIMP: "enable dnsupdate=yes in pdns.conf",
    dns.rcode.NOTZONE: "the alias is not in the zone",
}

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
        # Detected on the server at each update (see _find_zone)
        self.zone: dns.name.Name | None = None
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
        """Resolve the DNS server address, preferring IPv4.

        IPv4 is preferred to keep the source address used before IPv6
        support (PowerDNS allow-dnsupdate-from is often IPv4 only).
        IPv6 is used only when the server has no IPv4 address.
        """
        infos = socket.getaddrinfo(
            self.server, 53, type=socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP
        )
        if not infos:
            raise CannotConnect(f"Unable to resolve {self.server}")
        infos.sort(key=lambda info: info[0] != socket.AF_INET)
        return str(infos[0][4][0])

    def _do_dns_update(self, public_ips: dict[str, str]) -> set[str]:
        """Update only the records that changed. Returns the updated record types."""
        try:
            server_ip = self._resolve_server()

            # Query the authoritative server directly to avoid cache
            resolver = dns.resolver.Resolver(configure=False)
            resolver.nameservers = [server_ip]
            resolver.lifetime = DNS_TIMEOUT
            self.zone = self._find_zone(resolver, server_ip)

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
            response, source_ip = self._send_update(update, server_ip)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                message = (
                    f"DNS update of {', '.join(to_update)} for {self.alias} "
                    f"refused by {server_ip} "
                    f"(source {_describe_source(source_ip, public_ips)}): "
                    f"{dns.rcode.to_text(rcode)}"
                )
                if hint := RCODE_HINTS.get(rcode):
                    message += f" - {hint}"
                raise CannotConnect(message)
            return set(to_update)
        except (TimeoutError, dns.exception.Timeout) as error:
            raise TimeoutExpired(f"DNS update timeout for {self.alias}") from error
        except dns.exception.DNSException as error:
            raise CannotConnect(str(error)) from error
        except OSError as error:
            raise CannotConnect(str(error)) from error

    def _find_zone(
        self, resolver: dns.resolver.Resolver, server_ip: str
    ) -> dns.name.Name:
        """Ask the server which of its zones contains the alias (SOA lookup)."""
        try:
            zone = dns.resolver.zone_for_name(self.alias, resolver=resolver)
        except (dns.resolver.NoNameservers, dns.resolver.NoRootSOA) as error:
            # PowerDNS answers REFUSED for names outside its zones
            raise ZoneNotFound(
                f"No zone hosted by {server_ip} contains {self.alias}"
            ) from error
        _LOGGER.debug("Zone for %s on %s: %s", self.alias, server_ip, zone)
        return zone

    @staticmethod
    def _send_update(
        update: dns.update.UpdateMessage, server_ip: str
    ) -> tuple[dns.message.Message, str]:
        """Send a TSIG-signed update over UDP and return (response, source IP).

        Error responses (REFUSED, NOTAUTH...) are often not signed by the
        server. They are accepted only to report the rcode: an unsigned
        success is never trusted.
        """
        family = (
            socket.AF_INET6
            if ipaddress.ip_address(server_ip).version == 6
            else socket.AF_INET
        )
        wire = update.to_wire()
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(DNS_TIMEOUT)
            # Connected UDP socket: only datagrams from the server are received
            sock.connect((server_ip, DNS_PORT))
            sock.send(wire)
            source_ip = str(sock.getsockname()[0])
            while True:
                data = sock.recv(65535)
                try:
                    response = dns.message.from_wire(
                        data, keyring=update.keyring, request_mac=update.mac
                    )
                except dns.exception.FormError:
                    unsigned = dns.message.from_wire(data, keyring=False)
                    if not update.is_response(unsigned):
                        continue
                    if unsigned.rcode() == dns.rcode.NOERROR:
                        raise CannotConnect(
                            f"Unsigned success response from {server_ip}, ignored"
                        ) from None
                    return unsigned, source_ip
                if update.is_response(response):
                    return response, source_ip


def _describe_source(source_ip: str, public_ips: dict[str, str]) -> str:
    """Describe the update source address, as seen by the server.

    Behind NAT the local address is private: the server sees the public one.
    """
    address = ipaddress.ip_address(source_ip)
    if address.is_global:
        return source_ip
    public = public_ips.get("A" if address.version == 4 else "AAAA")
    if public:
        return f"{source_ip}, seen as {public} behind NAT"
    return f"{source_ip}, seen as your public IPv{address.version} behind NAT"


class PDNSFailed(Exception):
    """Error to indicate there is invalid pdns communication."""


class DetectionFailed(PDNSFailed):
    """Error to indicate public IP retrieval failed."""


class CannotConnect(PDNSFailed):
    """Error to indicate we cannot connect."""


class ZoneNotFound(CannotConnect):
    """Error to indicate the server hosts no zone containing the alias."""


class TimeoutExpired(PDNSFailed):
    """Error to indicate a timeout occurred."""
