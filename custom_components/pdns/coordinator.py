"""Coordinator for PDNS."""
from __future__ import annotations

from datetime import timedelta
import logging
from typing import Any

from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.update_coordinator import DataUpdateCoordinator, UpdateFailed

from .const import (
    CONF_ALIAS,
    CONF_PDNSSRV,
    CONF_TSIG_ALGORITHM,
    CONF_TTL,
    DEFAULT_ALGORITHM,
    DEFAULT_TTL,
    DOMAIN,
)
from .pdns import PDNS, PDNSFailed

_LOGGER = logging.getLogger(__name__)

SCAN_INTERVAL = 600


class PDNSDataUpdateCoordinator(DataUpdateCoordinator):
    """Define an object to fetch data."""

    def __init__(self, hass: HomeAssistant, entry: ConfigEntry) -> None:
        """Class to manage fetching data API."""
        super().__init__(
            hass, _LOGGER, name=DOMAIN, update_interval=timedelta(seconds=SCAN_INTERVAL)
        )
        self.api = PDNS(
            servername=entry.data.get(CONF_PDNSSRV),
            alias=entry.data.get(CONF_ALIAS),
            username=entry.data.get(CONF_USERNAME),
            password=entry.data.get(CONF_PASSWORD),
            algorithm=entry.data.get(CONF_TSIG_ALGORITHM, DEFAULT_ALGORITHM),
            ttl=entry.data.get(CONF_TTL, DEFAULT_TTL),
            session=async_create_clientsession(hass),
        )

    async def _async_update_data(self) -> dict[str, Any]:
        try:
            return await self.api.async_update()
        except PDNSFailed as error:
            raise UpdateFailed from error
