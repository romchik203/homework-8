import os
from scapy.all import sniff, wrpcap, Raw, TCP

captured_packets = []


def parse_http(data: str):
    """Разобрать первую строку HTTP и заголовки."""
    lines = data.split("\r\n")
    if not lines:
        return

    first = lines[0]

    # Первая строка: запрос или ответ
    if first.startswith("GET ") or first.startswith("POST "):
        parts = first.split(" ", 2)
        if len(parts) == 3:
            method, path, version = parts
            print(f"[HTTP-REQUEST] method={method}, path={path}, version={version}")
        else:
            print(f"[HTTP-REQUEST] {first}")
    elif first.startswith("HTTP/"):
        parts = first.split(" ", 2)
        if len(parts) >= 2:
            version, status = parts[0], parts[1]
            print(f"[HTTP-RESPONSE] version={version}, status={status}")
        else:
            print(f"[HTTP-RESPONSE] {first}")
    else:
        # Это не похоже на первую строку HTTP, выходим
        return

    print("[HEADERS]")
    for line in lines[1:]:
        if line == "":
            break
        print("  " + line)
    print()


def show_http_payload(pkt):
    """Попробовать вытащить HTTP-данные из пакета и распарсить их."""
    if pkt.haslayer(Raw) and pkt.haslayer(TCP):
        try:
            data = pkt[Raw].load.decode("utf-8", errors="ignore")
        except Exception:
            return

        if "HTTP/" in data or "Host:" in data:
            print("=" * 80)
            parse_http(data)


def process_packet(pkt):
    """Коллбэк для каждого пакета."""
    captured_packets.append(pkt)
    show_http_payload(pkt)


def main():
    print("[*] Запуск перехвата HTTP-трафика...")
    try:
        # Пока общий tcp, чтобы точно что-то поймать
        sniff(filter="tcp", prn=process_packet, store=False)
    except KeyboardInterrupt:
        pass
    finally:
        print("\n[*] Остановка перехвата, сохраняю pcap...")
        filename = "traffic_raw.pcap"
        wrpcap(filename, captured_packets)
        full_path = os.path.abspath(filename)
        print(f"[*] Готово: {full_path}")


if __name__ == "__main__":
    main()
