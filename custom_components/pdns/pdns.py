"""PDNS Api."""

from __future__ import annotations

import asyncio
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
from aiohttp import ClientError, ClientSession

MYIP_CHECK = "https://v4.ident.me/"

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
        session: ClientSession = None,
    ) -> None:
        """Initialize."""
        self.server = servername
        alias_name = dns.name.from_text(alias)
        self.alias = alias_name
        self.zone = alias_name.parent()
        self.algorithm = algorithm
        self.ttl = ttl
        self.session = session if session else ClientSession()
        self._key_name = dns.name.from_text(username)
        # TSIG keys from BIND/PowerDNS often lack base64 padding
        padded_secret = password + "=" * (-len(password) % 4)
        self._keyring = dns.tsigkeyring.from_text({username: padded_secret})

    async def async_update(self) -> dict[str, Any]:
        """Update DNS record via RFC 2136 dynamic update with TSIG."""
        public_ip = await self._async_get_public_ip()
        updated = await asyncio.get_running_loop().run_in_executor(
            None, self._do_dns_update, public_ip
        )
        if updated:
            _LOGGER.debug("TSIG update: %s -> %s (zone: %s)", self.alias, public_ip, self.zone)
        else:
            _LOGGER.debug("TSIG no change: %s already points to %s", self.alias, public_ip)
        return {
            "state": f"good {public_ip}" if updated else f"nochg {public_ip}",
            "public_ip": public_ip,
            "last_seen": datetime.now(),
        }

    async def _async_get_public_ip(self) -> str:
        """Get public IP address."""
        try:
            response = await self.session.get(MYIP_CHECK)
            if response.status != 200:
                raise CannotConnect(f"Can't fetch public ip ({response.status})")
            public_ip = await response.text()
            _LOGGER.debug("Public IP: %s", public_ip)
            return public_ip
        except asyncio.TimeoutError as error:
            raise TimeoutExpired("Timeout to get public ip address") from error
        except ClientError as error:
            raise DetectionFailed(str(error)) from error

    def _do_dns_update(self, ip: str) -> bool:
        """Check current record and update only if needed. Returns True if updated."""
        try:
            server_ip = socket.gethostbyname(self.server)

            # Query the authoritative server directly to avoid cache
            try:
                resolver = dns.resolver.Resolver(configure=False)
                resolver.nameservers = [server_ip]
                answers = resolver.resolve(self.alias, "A")
                if {rdata.address for rdata in answers} == {ip}:
                    return False
            except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.exception.DNSException):
                pass  # record missing or unresolvable — proceed with update

            update = dns.update.Update(
                self.zone,
                keyring=self._keyring,
                keyname=self._key_name,
                keyalgorithm=self.algorithm,
            )
            update.replace(self.alias, self.ttl, "A", ip)
            response = dns.query.udp(update, server_ip, timeout=10)
            rcode = response.rcode()
            if rcode != dns.rcode.NOERROR:
                raise CannotConnect(f"DNS update failed: {dns.rcode.to_text(rcode)}")
            return True
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
