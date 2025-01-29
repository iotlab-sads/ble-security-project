import dbus
import dbus.mainloop.glib
import dbus.service
from gi.repository import GLib
import subprocess
import re
import time

BLUEZ_SERVICE_NAME = "org.bluez"
ADAPTER_INTERFACE = "org.bluez.Adapter1"
LE_ADVERTISING_MANAGER_IFACE = "org.bluez.LEAdvertisingManager1"
LE_ADVERTISEMENT_IFACE = "org.bluez.LEAdvertisement1"


class IBeaconAdvertisement(dbus.service.Object):
    PATH_BASE = "/org/bluez/example/advertisement"

    def __init__(self, bus, index, uuid, major, minor, tx_power):
        self.path = self.PATH_BASE + str(index)
        self.bus = bus
        self.ad_type = "peripheral"

        self.manufacturer_data = dbus.Dictionary(
            {
                0x004C: dbus.Array(
                    [
                        0x02,
                        0x15,
                        *self.uuid_to_bytes(uuid),
                        (major >> 8) & 0xFF,
                        major & 0xFF,
                        (minor >> 8) & 0xFF,
                        minor & 0xFF,
                        tx_power & 0xFF,
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


def set_custom_mac_vendor_command(new_mac):
    """사용자 발견 방법으로 MAC 주소 변경"""
    try:
        # MAC 주소 파싱 및 바이트 순서 변환
        mac_parts = new_mac.replace(":", "")[-12:]  # 마지막 6바이트 추출
        reversed_bytes = [
            int(mac_parts[i : i + 2], 16)
            for i in range(10, -1, -2)  # 역순으로 2자리씩 처리
        ]

        # HCI Vendor 명령 구성 (0x3F 0x001)
        ogf = 0x3F
        ocf = 0x001
        cmd_bytes = [ogf, ocf] + reversed_bytes

        # hcitool 명령 실행
        subprocess.run(
            ["sudo", "hcitool", "cmd"] + [f"0x{b:02x}" for b in cmd_bytes], check=True
        )

        # 블루투스 서비스 재시작
        subprocess.run(
            ["sudo", "systemctl", "restart", "bluetooth.service"], check=True
        )
        time.sleep(2)  # 재시작 대기

        print(f"MAC 주소 변경 완료: {new_mac}")
        return True
    except Exception as e:
        print(f"MAC 주소 변경 실패: {e}")
        return False


def get_current_mac():
    """현재 MAC 주소 확인"""
    try:
        output = subprocess.check_output(["hciconfig", "hci0"]).decode()
        return re.search(r"BD Address: ([\dA-F:]+)", output).group(1)
    except:
        return "Unknown"


def main():
    # MAC 주소 변경
    target_mac = "03:23:45:67:89:AB"  # 원하는 주소로 변경
    if not set_custom_mac_vendor_command(target_mac):
        print("경고: MAC 주소 변경에 실패했지만 계속 진행합니다.")

    # 실제 변경된 MAC 확인
    current_mac = get_current_mac()
    print(f"현재 MAC 주소: {current_mac}")

    # 나머지 BLE 광고 설정
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    try:
        ad_manager = dbus.Interface(
            bus.get_object(BLUEZ_SERVICE_NAME, "/org/bluez/hci0"),
            LE_ADVERTISING_MANAGER_IFACE,
        )

        # iBeacon 파라미터 설정
        beacon = IBeaconAdvertisement(
            bus, 0, "12345678-1234-1234-1234-1234567890AB", 1, 1, -59
        )

        # 광고 등록
        ad_manager.RegisterAdvertisement(
            beacon.get_path(),
            {},
            reply_handler=lambda: print("광고 시작 성공"),
            error_handler=lambda e: print(f"광고 시작 실패: {e}"),
        )

        # 메인 루프 실행
        GLib.MainLoop().run()

    except Exception as e:
        print(f"에러 발생: {e}")
    finally:
        ad_manager.UnregisterAdvertisement(beacon)


if __name__ == "__main__":
    main()
