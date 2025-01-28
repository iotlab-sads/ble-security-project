import subprocess
import json
import sys
import statistics
import os
from pymongo import MongoClient
from tabulate import tabulate
from wcwidth import wcswidth
from pprint import pprint

def save_to_mongodb(database_name, collection_name, data):
    """
    MongoDB에 데이터를 저장합니다.
    :param database_name: MongoDB 데이터베이스 이름
    :param collection_name: MongoDB 컬렉션 이름
    :param data: 저장할 데이터 (딕셔너리 형식)
    """
    try:
        client = MongoClient("mongodb://localhost:27017/")  # 로컬 MongoDB에 연결. 포트 27018로 열어놨는데 mongodb는 주로 27017.
        db = client[database_name]
        collection = db[collection_name]
        collection.insert_one(data)  # 데이터 저장
        print("MongoDB 저장 성공:", data)
    except Exception as e:
        print("MongoDB 저장 오류:", e)
    finally:
        client.close()


def find_interface():
    print("Finding nRF Sniffer interface...")
    """
    nRF Sniffer for Bluetooth LE 장치의 인터페이스 이름을 찾습니다.

    Returns:
        str: 찾은 인터페이스 이름 (예: /dev/ttyACM0-4.2) 또는 None (찾지 못한 경우).
    """
    try:
        # Wireshark 설치 경로에서 tshark 실행 (경로가 다를 수 있음)
        result = subprocess.run(
            ["tshark", "-D"], capture_output=True, text=True, check=True
        )
        for line in result.stdout.splitlines():
            if "nRF Sniffer for Bluetooth LE" in line:
                parts = line.split()
                if len(parts) > 1:
                    interface = parts[1].strip()
                    print(f"Found nRF Sniffer interface: {interface}")
                    return interface
    except FileNotFoundError:
        print(
            "Error: tshark not found. Please make sure it is installed and in your PATH."
        )
        return None
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark -D: {e}")
        return None
    print("Error: Could not find nRF Sniffer interface.")
    return None


import uuid


def transform_uuid(uuid_str):
    """
    UUID 문자열을 입력받아 특정 형식으로 변환합니다.

    Args:
      uuid_str: 변환할 UUID 문자열 (예: "12345678-1234-1234-1234-1234567890AB")

    Returns:
      변환된 문자열 (예: "02:15:12:34:56:78:12:34:12:34:12:34:12:34:56:78:90:ab:00:01:00:01:c5")
    """

    try:
        # UUID 문자열을 UUID 객체로 변환
        uuid_obj = uuid.UUID(uuid_str)

        # UUID 객체를 바이트 배열로 변환
        uuid_bytes = uuid_obj.bytes

        # 바이트 배열을 16진수 문자열로 변환하고 콜론으로 구분
        hex_str = uuid_bytes.hex()
        hex_parts = [hex_str[i : i + 2] for i in range(0, len(hex_str), 2)]

        # 원하는 형식으로 조합
        result = "02:15:" + ":".join(hex_parts) + ":00:01:00:01:c5"

        return result
    except ValueError:
        return "Invalid UUID format"


def parse_ble_packets(
    interface, advertising_address, uuid_filter, target_num_packet=20
):
    """
    BLE 패킷을 JSON 형식으로 캡처하고 특정 광고 주소(ADV_IND)에 대해 37, 38, 39 채널에서 RSSI 평균과 Delta Time 평균을 계산.
    각 채널별로 20개의 패킷을 수집한 후 RSSI 평균과 Delta Time 평균을 계산.
    모든 채널의 결과가 수집되면 종합하여 표 형태로 출력하고 프로그램 종료.
    :param interface: Bluetooth 인터페이스 이름
    :param advertising_address: 필터링할 광고 주소 (예: "72:cf:4d:7d:8e:58")
    """
    cmd = ["tshark", "-i", interface, "-T", "json"]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
        universal_newlines=True,
    )

    print(
        f"BLE 패킷 캡처 시작 (인터페이스: {interface}, 광고 주소: {advertising_address}, 필터: ADV_IND)..."
    )

    channel_data = {
        37: {
            "rssi": [],
            "timestamps": [],
            "packet_count": 0,
            "last_timestamp": 0.0,
        },
        38: {
            "rssi": [],
            "timestamps": [],
            "packet_count": 0,
            "last_timestamp": 0.0,
        },
        39: {
            "rssi": [],
            "timestamps": [],
            "packet_count": 0,
            "last_timestamp": 0.0,
        },
    }

    channel_results = {}  # 채널별 계산 결과를 저장할 딕셔너리
    json_buffer = []
    all_channels_ready = False  # 모든 채널이 20개 이상 패킷을 받았는지 여부
    B = True

    try:
        for line in process.stdout:
            try:
                if line.strip() == "{" and json_buffer:
                    try:
                        # JSON 데이터 조립 및 파싱
                        json_data = json.loads("\n".join(json_buffer).rstrip(",\n"))

                        layers = json_data.get("_source", {}).get("layers", {})
                        nordic_ble = layers.get("nordic_ble", {})
                        btle = layers.get("btle", {})

                        # 채널 광고 주소 확인
                        channel_num = nordic_ble.get("nordic_ble.channel")
                        address = btle.get("btle.advertising_address")
                        timestamp = layers.get("frame", {}).get("frame.time_epoch")
                        rssi = nordic_ble.get("nordic_ble.rssi")
                        # 광고 패킷 타입 확인(ADV_IND여야 함)
                        pdu_type = btle.get("btle.advertising_header_tree", {}).get("btle.advertising_header.pdu_type")

                        try:
                            uuid = (
                                btle.get("btcommon.eir_ad.advertising_data")
                                .get("btcommon.eir_ad.entry")
                                .get("btcommon.eir_ad.entry.data")
                            )
                        except AttributeError:
                            uuid = "Unknown"

                        is_valid = True
                        if advertising_address != "all":
                            is_valid = address == advertising_address
                        if uuid_filter != "all":
                            is_valid = is_valid and uuid == transform_uuid(uuid_filter)

                        # 필터링: 채널 및 광고 주소
                        if is_valid and pdu_type == "0x00" and int(channel_num) in channel_data:
                            channel = int(channel_num)
                            data = channel_data[channel]

                            # RSSI 저장
                            data["rssi"].append(float(rssi))

                            # Time Delta 계산 (이전 패킷과의 시간 차이)
                            if (
                                data["packet_count"] > 0
                            ):  # 첫 번째 패킷은 Time Delta 계산 안 함
                                data["timestamps"].append(
                                    float(timestamp) - data["last_timestamp"]
                                )

                            data["last_timestamp"] = float(timestamp)

                            # 패킷 카운트 증가
                            data["packet_count"] += 1

                            # 출력
                            print(
                                f"채널 {channel} 패킷 {data['packet_count']}: 광고 주소: {address}, RSSI: {rssi}, 타임스탬프: {timestamp}"
                            )

                            # 모든 채널이 20개 이상 패킷을 받았는지 확인
                            all_channels_ready = all(
                                channel_data[ch]["packet_count"] >= target_num_packet
                                for ch in channel_data
                            )

                            # 모든 채널이 준비되면 결과 출력 및 종료
                            if all_channels_ready:
                                for channel, data in channel_data.items():
                                    # 채널별 결과 계산 및 저장
                                    if channel not in channel_results:
                                        avg_rssi = statistics.mean(
                                            data["rssi"][1 : target_num_packet + 1]
                                        )  # 20개 까지 자르기
                                        avg_delta_time = statistics.mean(
                                            data["timestamps"][:target_num_packet]
                                        )  # 20개로 자르기
                                        pprint(data["timestamps"][:target_num_packet])
                                        std_dev_delta_time = statistics.stdev(
                                            data["timestamps"][:target_num_packet]
                                        )
                                        channel_results[channel] = {
                                            "channel": channel,
                                            "received_packets": data["packet_count"],
                                            "avg_rssi": avg_rssi,
                                            "avg_delta_time": avg_delta_time,
                                            "std_dev_delta_time": std_dev_delta_time,
                                        }

                                # 표 형식으로 결과 출력
                                table_data = []
                                for result in channel_results.values():
                                    excess_packets = (
                                        result["received_packets"] - target_num_packet
                                    )  # 초과 패킷 수 계산
                                    table_data.append(
                                        [
                                            result["channel"],
                                            result["received_packets"],
                                            excess_packets,
                                            result["avg_rssi"],
                                            result["avg_delta_time"],
                                            result["std_dev_delta_time"],
                                        ]
                                    )
                                # 헤더 행을 별도로 구성
                                headers = [
                                    "채널",
                                    "수신 패킷",
                                    "초과 패킷",
                                    "RSSI 평균",
                                    "Delta Time 평균 (s)",
                                    "Delta Time 표준편차 (s)",
                                ]

                                # 헤더의 너비 계산
                                header_widths = [wcswidth(header) for header in headers]

                                # 데이터 행의 너비 계산
                                data_widths = []
                                for row in table_data:
                                    row_widths = [wcswidth(str(cell)) for cell in row]
                                    data_widths.append(row_widths)

                                # 최대 너비 계산
                                max_widths = header_widths
                                for row_widths in data_widths:
                                    max_widths = [
                                        max(w1, w2)
                                        for w1, w2 in zip(max_widths, row_widths)
                                    ]

                                # adjusted_table_data 생성 부분 수정
                                adjusted_table_data = []
                                for row in table_data:
                                    adjusted_row = []
                                    for i, cell in enumerate(row):
                                        cell_str = str(cell)
                                        cell_width = wcswidth(cell_str)
                                        padding = max_widths[i] - cell_width
                                        adjusted_row.append(cell_str + " " * padding)
                                    adjusted_table_data.append(adjusted_row)

                                # 헤더와 adjusted_table_data 사용하여 테이블 생성
                                table = tabulate(
                                    adjusted_table_data,
                                    headers=headers,
                                    tablefmt="fancy_grid",
                                    numalign="center",
                                    stralign="center",
                                )

                                print("\n모든 채널의 평균 계산 결과:")
                                print(table)
                                ### mongodb에 table 저장
                                # 전체 채널의 avg_rssi 평균 및 min_delta_time 계산
                                all_avg_rssi = statistics.mean(
                                    result["avg_rssi"] for result in channel_results.values()
                                )
                                all_min_delta_time = min(
                                    result["std_dev_delta_time"] for result in channel_results.values()
                                )

                                # MongoDB에 하나의 문서 저장
                                save_to_mongodb(
                                    "ble_data",  # MongoDB 데이터베이스 이름
                                    "uuid_analysis_results",  # MongoDB 컬렉션 이름
                                    {
                                        "uuid": uuid_filter,
                                        "advertising_address": advertising_address,
                                        "avg_rssi": all_avg_rssi,
                                        "min_delta_time": all_min_delta_time,
                                    },
                                )                                

                                # 프로세스 종료
                                process.terminate()
                                sys.exit(0)

                    except json.JSONDecodeError as e:
                        print(f"JSON Decode Error: {e}")
                    finally:
                        json_buffer = []  # 버퍼 초기화
                json_buffer.append(line.strip())
            except json.JSONDecodeError:
                continue

    except KeyboardInterrupt:
        print("\nBLE 패킷 캡처 종료.")
        process.terminate()
        sys.exit(1)


def main():
    if len(sys.argv) < 3:
        print(
            "사용법: python packet.py <인터페이스 이름/auto> <광고 주소/all> <UUID/all> [수집할 패킷 수] "
        )
        print("  <인터페이스 이름/auto>: Bluetooth 인터페이스 이름 또는 'auto'")
        print("       'auto'를 입력하면 자동으로 nRF Sniffer 인터페이스를 찾습니다.")
        print(
            "  <광고 주소/all>: 필터링할 BLE 장치의 광고 주소 (예: 72:cf:4d:7d:8e:58) 또는 'all'"
        )
        print("       'all'을 입력하면 모든 광고 주소를 대상으로 합니다.")
        print(
            "  <UUID/all>: 필터링할 BLE 장치의 UUID (예: 12345678-1234-1234-1234-1234567890AB) 또는 'all'"
        )
        print("       'all'을 입력하면 모든 UUID를 대상으로 합니다.")
        print("  [수집할 패킷 수]: (선택 사항) 각 채널별로 수집할 패킷 수 (기본값: 20)")
        sys.exit(1)

    interface_or_uuid = sys.argv[1]
    advertising_address = sys.argv[2]
    uuid_filter = sys.argv[3]
    target_num_packet = int(sys.argv[4]) if len(sys.argv) > 4 else 20

    print(
        f"인터페이스/UUID: {interface_or_uuid}, 광고 주소: {advertising_address}, "
        f"수집할 패킷 수: {target_num_packet}, UUID 필터: {uuid_filter}"
    )

    if interface_or_uuid == "auto":
        interface = find_interface()
        if not interface:
            sys.exit(1)
    else:
        interface = interface_or_uuid

    parse_ble_packets(interface, advertising_address, uuid_filter, target_num_packet)


if __name__ == "__main__":
    main()
