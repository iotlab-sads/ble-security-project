import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import subprocess
import re

BLUEZ_SERVICE_NAME = "org.bluez"
ADAPTER_INTERFACE = "org.bluez.Adapter1"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
LE_ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"


class IBeaconAdvertisement(dbus.service.Object):
    PATH_BASE = "/org/bluez/example/advertisement"

    def __init__(self, bus, index, uuid, major, minor, tx_power):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.ad_type = "broadcast"

        # iBeacon 데이터 생성
        self.manufacturer_data = dbus.Dictionary(
            {
                0x004C: dbus.Array(
                    [  # Apple Company ID
                        0x02,
                        0x15,  # iBeacon Type + Length
                        *self.uuid_to_bytes(uuid),  # UUID (16 bytes)
                        (major >> 8) & 0xFF,
                        major & 0xFF,  # Major (2 bytes)
                        (minor >> 8) & 0xFF,
                        minor & 0xFF,  # Minor (2 bytes)
                        tx_power & 0xFF,  # TX Power (1 byte)
                    ],
                    signature="y",
                )
            },
            signature="qv",
        )

        dbus.service.Object.__init__(self, bus, self.path)

    def get_path(self):
        return dbus.ObjectPath(self.path)

    @staticmethod
    def uuid_to_bytes(uuid):
        """Convert UUID string to byte array."""
        if len(uuid) != 36 or uuid.count("-") != 4:
            raise ValueError(f"Invalid UUID format: {uuid}")

        cleaned_uuid = uuid.replace("-", "")
        return [
            int(cleaned_uuid[i : i + 2], 16) for i in range(0, len(cleaned_uuid), 2)
        ]

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature="ss", out_signature="v")
    def Get(self, interface, property):
        if interface != LE_ADVERTISEMENT_IFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs"
            )
        if property == "Type":
            return self.ad_type
        if property == "ManufacturerData":
            return self.manufacturer_data

    @dbus.service.method(dbus.PROPERTIES_IFACE, in_signature="", out_signature="a{sv}")
    def GetAll(self, interface):
        if interface != LE_ADVERTISEMENT_IFACE:
            raise dbus.exceptions.DBusException(
                "org.freedesktop.DBus.Error.InvalidArgs"
            )
        return {
            "Type": self.ad_type,
            "ManufacturerData": self.manufacturer_data,
        }

    @dbus.service.method(LE_ADVERTISEMENT_IFACE, in_signature="", out_signature="")
    def Release(self):
        print(f"{self.path}: Released!")


def register_ad_cb():
    print("Advertisement registered successfully")


def register_ad_error_cb(error):
    print(f"Failed to register advertisement: {error}")
    mainloop.quit()


def get_mac_address():
    """Get the MAC address of the Bluetooth adapter."""
    try:
        output = subprocess.check_output(
            ["hciconfig", "hci0", "mad"], stderr=subprocess.STDOUT
        ).decode("utf-8")
        mac_address = re.search(r"BD Address:\s+([0-9A-F:]+)", output).group(1)
        return mac_address
    except (subprocess.CalledProcessError, AttributeError):
        return "Unknown"


def get_service_data_string(manufacturer_data):
    """Convert manufacturer data to a formatted string."""
    service_data_list = []
    for key, value in manufacturer_data.items():
        key_str = f"0x{key:04X}"
        value_str = " ".join([f"0x{byte:02X}" for byte in value])
        service_data_list.append(f"{key_str}: {value_str}")
    return ", ".join(service_data_list)


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)

    bus = dbus.SystemBus()
    adapter_path = "/org/bluez/hci0"

    ad_manager = dbus.Interface(
        bus.get_object(BLUEZ_SERVICE_NAME, adapter_path),
        LE_ADVERTISING_MANAGER_IFACE,
    )

    # iBeacon 파라미터 설정
    uuid = "12345678-1234-1234-1234-1234567890AB"  # iBeacon UUID
    major = 1  # Major 값
    minor = 1  # Minor 값
    tx_power = -59  # TX Power (1미터 거리의 RSSI 값)

    # iBeacon Advertisement 생성
    beacon = IBeaconAdvertisement(bus, 0, uuid, major, minor, tx_power)

    # 시작 시 필요한 데이터 출력
    mac_address = get_mac_address()
    service_data_str = get_service_data_string(beacon.manufacturer_data)
    print("-" * 30)
    print("Starting iBeacon Simulation")
    print("-" * 30)
    print(f"MAC Address: {mac_address}")
    print(f"UUID: {uuid}")
    print(f"Major: {major}")
    print(f"Minor: {minor}")
    print(f"TX Power: {tx_power}")
    print(f"Service Data: {service_data_str}")
    print("-" * 30)

    ad_manager.RegisterAdvertisement(
        beacon.get_path(),
        {},
        reply_handler=register_ad_cb,
        error_handler=register_ad_error_cb,
    )

    try:
        global mainloop
        mainloop = GLib.MainLoop()
        mainloop.run()
    except KeyboardInterrupt:
        print("Terminating...")
        ad_manager.UnregisterAdvertisement(beacon)


if __name__ == "__main__":
    main()
