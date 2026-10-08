import re

XML_FILE = "_sysmon_records.xml"
MALWARE_NAME = "Lapor_SPT_Pajak.exe"


def get_data(event, name):
    pattern = r'Name="' + re.escape(name) + r'">(.*?)</Data>'
    match = re.search(pattern, event, re.DOTALL)
    return match.group(1).strip() if match else ""


with open(XML_FILE, "r", encoding="utf-8") as f:
    records = f.read().split("<Event ")


results = []

for event in records:

    # Sysmon Event ID 11 = FileCreate
    event_id = re.search(
        r"<EventID[^>]*>(\d+)</EventID>",
        event
    )

    if not event_id or event_id.group(1) != "11":
        continue

    image = get_data(event, "Image")
    target = get_data(event, "TargetFilename")
    utc_time = get_data(event, "UtcTime")

    # Cari FileCreate yang dibuat oleh malware
    if MALWARE_NAME.lower() in image.lower():

        print("=" * 80)
        print("UtcTime :", utc_time)
        print("Image   :", image)
        print("File    :", target)
        print()

        results.append(target)


print("=" * 80)
print("FILES CREATED BY", MALWARE_NAME)
print("=" * 80)

for file in sorted(set(results), key=str.lower):
    print(file)