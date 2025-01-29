import uuid
import subprocess
import json
import sys
import time
from pymongo import MongoClient
import smtplib
from email.mime.text import MIMEText
from datetime import datetime

# MongoDB 설정
MONGO_URI = "mongodb://localhost:27017/"
DB_NAME = "ble_data"
COLLECTION_NAME = "uuid_analysis_results"

# 이메일 설정
EMAIL_CONFIG = {
    "smtp_server": "smtp.gmail.com",
    "smtp_port": 587,
    "sender_email": "your_email@gmail.com",
    "sender_password": "your_app_specific_password",
    "receiver_email": "receiver_email@example.com",
}


def find_interface():
    """nRF Sniffer 인터페이스 자동 탐색"""
    try:
        result = subprocess.run(
            ["tshark", "-D"], capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if "nRF Sniffer for Bluetooth LE" in line:
                parts = line.split()
                if len(parts) > 1:
                    return parts[1].strip()
        return None
    except Exception as e:
        print(f"인터페이스 찾기 오류: {e}")
        return None


def send_alert_email(device_info, delta_time, min_delta):
    """스푸핑 탐지 알림 이메일 전송"""
    subject = f"[BLE Spoof Alert] {device_info}"
    body = f"""
    BLE 패킷 스푸핑이 탐지되었습니다!

    디바이스 정보: {device_info}
    탐지 시간: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
    측정 간격: {delta_time:.6f} 초
    허용 최소 간격: {min_delta:.6f} 초
    """

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = EMAIL_CONFIG["sender_email"]
    msg["To"] = EMAIL_CONFIG["receiver_email"]

    try:
        with smtplib.SMTP(
            EMAIL_CONFIG["smtp_server"], EMAIL_CONFIG["smtp_port"]
        ) as server:
            server.starttls()
            server.login(EMAIL_CONFIG["sender_email"], EMAIL_CONFIG["sender_password"])
            server.sendmail(
                EMAIL_CONFIG["sender_email"],
                EMAIL_CONFIG["receiver_email"],
                msg.as_string(),
            )
        print("경고 이메일 전송 성공")
    except Exception as e:
        print(f"이메일 전송 실패: {e}")


def get_min_delta(device_id):
    """MongoDB에서 디바이스의 최소 허용 간격 조회"""
    client = MongoClient(MONGO_URI)
    db = client[DB_NAME]
    collection = db[COLLECTION_NAME]

    query = {"$or": [{"uuid": device_id}, {"advertising_address": device_id}]}
    entry = collection.find_one(query)
    client.close()

    return entry.get("advertising_interval") if entry else None


def monitor_ble_traffic(interface, target_addr, target_uuid):
    """BLE 트래픽 모니터링 및 이상 패킷 감지"""
    last_timestamps = {}

    cmd = ["tshark", "-i", interface, "-T", "json"]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        universal_newlines=True,
    )

    print(f"모니터링 시작 (인터페이스: {interface})...")
    print(f"대상 주소: {target_addr}, 대상 UUID: {target_uuid}")

    json_buffer = []
    for line in process.stdout:
        try:
            if line.strip() == "{" and json_buffer:
                packet = json.loads("\n".join(json_buffer).rstrip(",\n"))
                layers = packet.get("_source", {}).get("layers", {})
                btle = layers.get("btle", {})
                nordic_ble = layers.get("nordic_ble", {})

                # 패킷 정보 추출
                address = btle.get("btle.advertising_address")
                pdu_type = btle.get("btle.advertising_header_tree", {}).get(
                    "btle.advertising_header.pdu_type"
                )
                uuid_data = (
                    btle.get("btcommon.eir_ad.advertising_data", {})
                    .get("btcommon.eir_ad.entry", {})
                    .get("btcommon.eir_ad.entry.data")
                )
                timestamp = float(layers.get("frame", {}).get("frame.time_epoch", 0))
                channel = nordic_ble.get("nordic_ble.channel")

                # 필터링 조건 확인
                addr_match = (target_addr == "all") or (address == target_addr)
                uuid_match = (target_uuid == "all") or (
                    uuid_data == transform_uuid(target_uuid)
                )

                if (
                    addr_match
                    and uuid_match
                    and pdu_type == "0x00"
                    and channel in ["37", "38", "39"]
                ):
                    device_id = target_uuid if target_uuid != "all" else address
                    min_delta = get_min_delta(device_id)

                    if not min_delta:
                        continue

                    # 시간 간격 계산
                    last_time = last_timestamps.get(device_id)
                    current_time = timestamp

                    if last_time is not None:
                        delta = current_time - last_time

                        if delta < min_delta:
                            print(f"[!] 스푸핑 탐지! ({device_id})")
                            print(
                                f"    측정 간격: {delta:.6f}s < 허용 최소: {min_delta:.6f}s"
                            )
                            send_alert_email(device_id, delta, min_delta)

                    last_timestamps[device_id] = current_time

        except json.JSONDecodeError:
            pass
        finally:
            json_buffer = []
        json_buffer.append(line.strip())


def transform_uuid(uuid_str):
    """UUID 변환 함수 (기존 코드와 동일)"""
    try:
        uuid_obj = uuid.UUID(uuid_str)
        hex_str = uuid_obj.hex
        return f"02:15:{':'.join([hex_str[i:i+2] for i in range(0, len(hex_str), 2)])}:00:01:00:01:c5"
    except:
        return uuid_str


if __name__ == "__main__":
    # 인터페이스 자동 탐색
    interface = find_interface()
    if not interface:
        print("nRF Sniffer 인터페이스를 찾을 수 없습니다.")
        sys.exit(1)

    # 커맨드라인 인자 처리
    if len(sys.argv) < 3:
        print("사용법: python detect_spoof.py <target_address/all> <target_uuid/all>")
        print("예시: python detect_spoof.py all 12345678-1234-1234-1234-1234567890ab")
        sys.exit(1)

    target_addr = sys.argv[1]
    target_uuid = sys.argv[2].lower() if len(sys.argv) > 2 else "all"

    monitor_ble_traffic(interface, target_addr, target_uuid)
