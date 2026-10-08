import re
import os


XML_FILE = "_sysmon_records.xml"


def get_data(event, name):
    pattern = r'Name="' + re.escape(name) + r'">(.*?)</Data>'
    match = re.search(pattern, event, re.DOTALL)

    if match:
        return match.group(1)

    return ""


print("=" * 80)
print("SHORTWAY - Q2")
print("Finding the Malicious Program and PID")
print("=" * 80)
print()


if not os.path.exists(XML_FILE):

    print("[ERROR] File tidak ditemukan:")
    print(XML_FILE)

    print()
    print("Jalankan terlebih dahulu:")
    print("python Q2_parse_sysmon.py")

    exit()


print("[+] Reading:", XML_FILE)
print()


with open(XML_FILE, "r", encoding="utf-8") as f:
    records = f.read().split("<Event ")


print("Total records loaded:", len(records))
print()


total_event1 = 0
candidates = 0


for event in records:

    # ------------------------------------------------------------
    # Sysmon Event ID
    #
    # Format evidence:
    # <EventID Qualifiers="">1</EventID>
    # ------------------------------------------------------------

    event_id = re.search(
        r"<EventID[^>]*>(\d+)</EventID>",
        event
    )

    if not event_id:
        continue

    if event_id.group(1) != "1":
        continue

    total_event1 += 1

    # ------------------------------------------------------------
    # Ambil field Sysmon
    # ------------------------------------------------------------

    utc_time = get_data(event, "UtcTime")
    process_id = get_data(event, "ProcessId")
    image = get_data(event, "Image")
    parent_image = get_data(event, "ParentImage")
    command_line = get_data(event, "CommandLine")

    # ------------------------------------------------------------
    # Cari initial execution:
    #
    # Image       = executable dari Desktop
    # ParentImage = explorer.exe
    # ------------------------------------------------------------

    if (
        "\\Desktop\\" in image
        and parent_image.lower().endswith("explorer.exe")
    ):

        candidates += 1

        print("-" * 80)
        print(f"[CANDIDATE #{candidates}]")
        print("-" * 80)

        print("UtcTime     :", utc_time)
        print("ProcessId   :", process_id)
        print("Image       :", image)
        print("ParentImage :", parent_image)
        print("CommandLine :", command_line)
        print()


print("=" * 80)
print("SUMMARY")
print("=" * 80)

print("Event ID 1 records :", total_event1)
print("Candidates         :", candidates)
print()


if candidates == 0:

    print("[!] Event ID 1 ditemukan,")
    print("    tetapi belum ada kandidat Desktop + explorer.exe.")

else:

    print("[+] Kandidat initial execution ditemukan.")
    print()
    print("Untuk Q2 gunakan:")
    print("Image     = malicious program")
    print("ProcessId = PID")