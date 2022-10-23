"""binary sensor entities."""
from homeassistant.components.binary_sensor import (
    BinarySensorDeviceClass,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.update_coordinator import CoordinatorEntity

from . import DOMAIN, PDNSDataUpdateCoordinator


async def async_setup_entry(
    hass: HomeAssistant,
    config_entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    """Defer binary sensor setup to the shared sensor module."""
    coordinator = hass.data[DOMAIN][config_entry.entry_id]
    async_add_entities([DyndnsStatus(coordinator)])


class DyndnsStatus(CoordinatorEntity[PDNSDataUpdateCoordinator], BinarySensorEntity):
    """Representation of a status sensor."""

    _attr_device_class = BinarySensorDeviceClass.PROBLEM
    _attr_has_entity_name = True

    def __init__(self, coordinator):
        """Initialize the sensor."""
        super().__init__(coordinator)
        # self._attr_name = coordinator.config_entry.data["dns_alias"]
        self._attr_name = coordinator.config_entry.title
        self._attr_unique_id = coordinator.config_entry.entry_id
        self.coordinator = coordinator

    @property
    def is_on(self):
        """Return true if the binary sensor have a trouble."""
        return self.available is False

    @property
    def extra_state_attributes(self):
        """Return extra attributes."""
        return self.coordinator.data
