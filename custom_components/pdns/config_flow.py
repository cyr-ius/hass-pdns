"""Config flow to configure PowerDNS Dynhost."""
from __future__ import annotations

import logging

import voluptuous as vol

from homeassistant import config_entries
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_create_clientsession
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import (
    CONF_ALIAS,
    CONF_DNS_ZONE,
    CONF_PDNSSRV,
    CONF_TSIG_ALGORITHM,
    CONF_TTL,
    DEFAULT_ALGORITHM,
    DEFAULT_TTL,
    DOMAIN,
    TSIG_ALGORITHMS,
)
from .pdns import PDNS, CannotConnect, PDNSFailed, TimeoutExpired

_LOGGER = logging.getLogger(__name__)

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PDNSSRV): cv.string,
        vol.Required(CONF_DNS_ZONE): cv.string,
        vol.Required(CONF_ALIAS): cv.string,
        vol.Required(CONF_USERNAME): cv.string,
        vol.Required(CONF_PASSWORD): cv.string,
        vol.Required(CONF_TSIG_ALGORITHM, default=DEFAULT_ALGORITHM): SelectSelector(
            SelectSelectorConfig(
                options=TSIG_ALGORITHMS,
                mode=SelectSelectorMode.DROPDOWN,
            )
        ),
        vol.Optional(CONF_TTL, default=DEFAULT_TTL): cv.positive_int,
    }
)


class PDNSFlowHandler(config_entries.ConfigFlow, domain=DOMAIN):
    """Handle a config flow."""

    VERSION = 1
    CONNECTION_CLASS = config_entries.CONN_CLASS_LOCAL_POLL

    async def async_step_user(self, user_input=None):
        """Handle a flow initialized by the user."""
        errors = {}
        if user_input is not None:
            try:
                self._async_abort_entries_match(
                    {
                        CONF_PDNSSRV: user_input[CONF_PDNSSRV],
                        CONF_ALIAS: user_input[CONF_ALIAS],
                    }
                )
                client = PDNS(
                    servername=user_input[CONF_PDNSSRV],
                    zone=user_input[CONF_DNS_ZONE],
                    alias=user_input[CONF_ALIAS],
                    username=user_input[CONF_USERNAME],
                    password=user_input[CONF_PASSWORD],
                    algorithm=user_input[CONF_TSIG_ALGORITHM],
                    ttl=user_input[CONF_TTL],
                    session=async_create_clientsession(self.hass),
                )
                await client.async_update()
            except CannotConnect:
                errors["base"] = "login_incorrect"
            except TimeoutExpired:
                errors["base"] = "timeout"
            except PDNSFailed as err:
                errors["base"] = err.args[0]
            else:
                return self.async_create_entry(
                    title=f"PowerDNS ({user_input[CONF_ALIAS]})",
                    data=user_input,
                )

        return self.async_show_form(
            step_id="user", data_schema=DATA_SCHEMA, errors=errors
        )
