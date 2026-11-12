"""Config flow to configure PowerDNS Dynhost."""

import logging
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigEntry,
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
    OptionsFlowWithReload,
)
from homeassistant.const import CONF_PASSWORD, CONF_USERNAME
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.aiohttp_client import async_get_clientsession
from homeassistant.helpers.selector import (
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
)

from .const import (
    CONF_ALIAS,
    CONF_IP_VERSION,
    CONF_PDNSSRV,
    CONF_TSIG_ALGORITHM,
    CONF_TTL,
    DEFAULT_ALGORITHM,
    DEFAULT_IP_VERSION,
    DEFAULT_TTL,
    DOMAIN,
    IP_VERSION_BOTH,
    IP_VERSION_V4,
    IP_VERSION_V6,
    IP_VERSIONS,
    LEGACY_IP_VERSION,
    TSIG_ALGORITHMS,
)
from .pdns import (
    PDNS,
    CannotConnect,
    DetectionFailed,
    PDNSFailed,
    TimeoutExpired,
    ZoneNotFound,
)

_LOGGER = logging.getLogger(__name__)

IP_VERSION_SELECTOR = SelectSelector(
    SelectSelectorConfig(
        options=IP_VERSIONS,
        mode=SelectSelectorMode.LIST,
        translation_key=CONF_IP_VERSION,
    )
)

DATA_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_PDNSSRV): cv.string,
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
        vol.Required(CONF_IP_VERSION, default=DEFAULT_IP_VERSION): IP_VERSION_SELECTOR,
    }
)


RECORD_IP_VERSION = {"A": IP_VERSION_V4, "AAAA": IP_VERSION_V6}


def _build_client(hass: HomeAssistant, data: dict[str, Any], ip_version: str) -> PDNS:
    """Build a PDNS client from entry data."""
    return PDNS(
        servername=data[CONF_PDNSSRV],
        alias=data[CONF_ALIAS],
        username=data[CONF_USERNAME],
        password=data[CONF_PASSWORD],
        algorithm=data.get(CONF_TSIG_ALGORITHM, DEFAULT_ALGORITHM),
        ttl=data.get(CONF_TTL, DEFAULT_TTL),
        session=async_get_clientsession(hass),
        ip_version=ip_version,
    )


async def async_validate_update(
    hass: HomeAssistant, data: dict[str, Any], ip_version: str
) -> dict[str, str]:
    """Run a DNS update with the given settings and return form errors."""
    try:
        await _build_client(hass, data, ip_version).async_update()
    except PDNSFailed as error:
        _LOGGER.warning(
            "Validation of %s (%s) failed: %s", data[CONF_ALIAS], ip_version, error
        )
        if isinstance(error, ZoneNotFound):
            return {"base": "zone_not_found"}
        if isinstance(error, CannotConnect):
            return {"base": "login_incorrect"}
        if isinstance(error, TimeoutExpired):
            return {"base": "timeout"}
        if isinstance(error, DetectionFailed):
            return {"base": "detect_failed"}
        return {"base": "update_failed"}
    return {}


class DualStackCheckMixin:
    """Steps shared by config and options flows when IPv4 + IPv6 is selected.

    A first update is run and the status of each address family is shown.
    If one family fails, the user can fall back to the one that works.
    """

    hass: HomeAssistant
    _test_data: dict[str, Any]

    def _async_show_main_form(self, errors: dict[str, str]) -> ConfigFlowResult:
        """Show the main form again (with the previous input)."""
        raise NotImplementedError

    def _async_finish(self, ip_version: str) -> ConfigFlowResult:
        """Save the configuration with the chosen IP version."""
        raise NotImplementedError

    async def async_step_dual_check(self, user_input=None) -> ConfigFlowResult:
        """Detect IPv4 and IPv6, then run a first update if both are available."""
        client = _build_client(self.hass, self._test_data, IP_VERSION_BOTH)
        detected = await client.async_detect_public_ips()
        working = [rdtype for rdtype, ip in detected.items() if isinstance(ip, str)]
        placeholders = {
            "ipv4_status": _format_status(detected["A"]),
            "ipv6_status": _format_status(detected["AAAA"]),
        }

        if not working:
            return self._async_show_main_form({"base": "detect_failed"})

        if len(working) == len(detected):
            errors = await async_validate_update(
                self.hass, self._test_data, IP_VERSION_BOTH
            )
            if errors:
                return self._async_show_main_form(errors)
            return self.async_show_menu(  # type: ignore[attr-defined]
                step_id="dual_success",
                menu_options=["confirm_dual", "back"],
                description_placeholders=placeholders,
            )

        fallback = RECORD_IP_VERSION[working[0]]
        return self.async_show_menu(  # type: ignore[attr-defined]
            step_id="dual_partial",
            menu_options=[f"use_{fallback}", "back"],
            description_placeholders=placeholders,
        )

    # Home Assistant requires a step method for each shown step_id
    async def async_step_dual_success(self, user_input=None) -> ConfigFlowResult:
        """Status menu when both families work (re-runs the check)."""
        return await self.async_step_dual_check()

    async def async_step_dual_partial(self, user_input=None) -> ConfigFlowResult:
        """Status menu when one family fails (re-runs the check)."""
        return await self.async_step_dual_check()

    async def async_step_confirm_dual(self, user_input=None) -> ConfigFlowResult:
        """Keep IPv4 + IPv6."""
        return self._async_finish(IP_VERSION_BOTH)

    async def async_step_use_ipv4(self, user_input=None) -> ConfigFlowResult:
        """Fall back to IPv4 only."""
        return await self._async_fallback(IP_VERSION_V4)

    async def async_step_use_ipv6(self, user_input=None) -> ConfigFlowResult:
        """Fall back to IPv6 only."""
        return await self._async_fallback(IP_VERSION_V6)

    async def async_step_back(self, user_input=None) -> ConfigFlowResult:
        """Return to the main form."""
        return self._async_show_main_form({})

    async def _async_fallback(self, ip_version: str) -> ConfigFlowResult:
        """Run the update for a single family and save it."""
        self._test_data = {**self._test_data, CONF_IP_VERSION: ip_version}
        if errors := await async_validate_update(
            self.hass, self._test_data, ip_version
        ):
            return self._async_show_main_form(errors)
        return self._async_finish(ip_version)


def _format_status(result: str | PDNSFailed) -> str:
    """Format a detection result for display."""
    if isinstance(result, str):
        return f"✅ {result}"
    return f"❌ {result}"


class PDNSFlowHandler(DualStackCheckMixin, ConfigFlow, domain=DOMAIN):
    """Handle a config flow."""

    VERSION = 1

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> OptionsFlow:
        """Get the options flow for this handler."""
        return PDNSOptionsFlowHandler()

    async def async_step_user(self, user_input=None) -> ConfigFlowResult:
        """Handle a flow initialized by the user."""
        if user_input is None:
            return self._async_show_main_form({})

        self._async_abort_entries_match(
            {
                CONF_PDNSSRV: user_input[CONF_PDNSSRV],
                CONF_ALIAS: user_input[CONF_ALIAS],
            }
        )
        self._test_data = user_input
        if user_input[CONF_IP_VERSION] == IP_VERSION_BOTH:
            return await self.async_step_dual_check()

        if errors := await async_validate_update(
            self.hass, user_input, user_input[CONF_IP_VERSION]
        ):
            return self._async_show_main_form(errors)
        return self._async_finish(user_input[CONF_IP_VERSION])

    def _async_show_main_form(self, errors: dict[str, str]) -> ConfigFlowResult:
        schema = DATA_SCHEMA
        if previous := getattr(self, "_test_data", None):
            schema = self.add_suggested_values_to_schema(DATA_SCHEMA, previous)
        return self.async_show_form(step_id="user", data_schema=schema, errors=errors)

    def _async_finish(self, ip_version: str) -> ConfigFlowResult:
        data = {**self._test_data, CONF_IP_VERSION: ip_version}
        return self.async_create_entry(
            title=f"PowerDNS ({data[CONF_ALIAS]})", data=data
        )


class PDNSOptionsFlowHandler(DualStackCheckMixin, OptionsFlowWithReload):
    """Handle options (IP version to update)."""

    async def async_step_init(self, user_input=None) -> ConfigFlowResult:
        """Manage the options."""
        self._test_data = dict(self.config_entry.data)
        # The current choice comes from options first (see _async_show_main_form)
        self._test_data.pop(CONF_IP_VERSION, None)
        if user_input is None:
            return self._async_show_main_form({})

        ip_version = user_input[CONF_IP_VERSION]
        self._test_data[CONF_IP_VERSION] = ip_version
        if ip_version == IP_VERSION_BOTH:
            return await self.async_step_dual_check()

        if errors := await async_validate_update(
            self.hass, self._test_data, ip_version
        ):
            return self._async_show_main_form(errors)
        return self._async_finish(ip_version)

    def _async_show_main_form(self, errors: dict[str, str]) -> ConfigFlowResult:
        current = self._test_data.get(
            CONF_IP_VERSION,
            self.config_entry.options.get(
                CONF_IP_VERSION,
                self.config_entry.data.get(CONF_IP_VERSION, LEGACY_IP_VERSION),
            ),
        )
        schema = vol.Schema(
            {vol.Required(CONF_IP_VERSION, default=current): IP_VERSION_SELECTOR}
        )
        return self.async_show_form(step_id="init", data_schema=schema, errors=errors)

    def _async_finish(self, ip_version: str) -> ConfigFlowResult:
        return self.async_create_entry(data={CONF_IP_VERSION: ip_version})
