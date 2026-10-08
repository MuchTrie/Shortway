import re
import os
from Evtx.Evtx import Evtx

EVTX_FILE = "Microsoft-Windows-Sysmon%4Operational.evtx"


def get_data(xml, name):
    pattern = rf'<Data Name="{re.escape(name)}">(.*?)</Data>'
    match = re.search(pattern, xml, re.DOTALL)

    if match:
        return match.group(1)

    return ""


def main():

    if not os.path.exists(EVTX_FILE):
        print("[ERROR] File Sysmon tidak ditemukan:")
        print(EVTX_FILE)
        return

    print("=" * 80)
    print("SHORTWAY - Q2 ANALYSIS")
    print("=" * 80)
    print()

    total_records = 0
    event1_count = 0
    candidates = 0

    try:

        with Evtx(EVTX_FILE) as log:

            for record in log.records():

                total_records += 1

                xml = record.xml()

                # Sysmon Event ID 1 = Process Create
                if "<EventID>1</EventID>" not in xml:
                    continue

                event1_count += 1

                utc_time = get_data(xml, "UtcTime")
                process_id = get_data(xml, "ProcessId")
                image = get_data(xml, "Image")
                parent_image = get_data(xml, "ParentImage")
                command_line = get_data(xml, "CommandLine")

                # Cari proses yang dijalankan dari Desktop
                # dengan parent process explorer.exe
                if (
                    "\\Desktop\\" in image
                    and parent_image.lower().endswith("explorer.exe")
                ):

                    candidates += 1

                    print("-" * 80)
                    print(f"[CANDIDATE #{candidates}]")
                    print("-" * 80)

                    print(f"UtcTime     : {utc_time}")
                    print(f"ProcessId   : {process_id}")
                    print(f"Image       : {image}")
                    print(f"ParentImage : {parent_image}")
                    print(f"CommandLine : {command_line}")
                    print()

    except Exception as e:

        print("[ERROR] Gagal membaca EVTX.")
        print(type(e).__name__)
        print(e)
        return

    print("=" * 80)
    print("SUMMARY")
    print("=" * 80)

    print(f"Total records read : {total_records}")
    print(f"Event ID 1         : {event1_count}")
    print(f"Candidates         : {candidates}")


if __name__ == "__main__":
    main()