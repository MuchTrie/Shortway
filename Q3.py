import re

XML_FILE = "_sysmon_records.xml"

def get_data(event, name):
    pattern = r'Name="' + re.escape(name) + r'">(.*?)</Data>'
    match = re.search(pattern, event, re.DOTALL)
    return match.group(1) if match else ""

with open(XML_FILE, "r", encoding="utf-8") as f:
    records = f.read().split("<Event ")

count = 0

for event in records:

    event_id = re.search(r"<EventID[^>]*>(\d+)</EventID>", event)

    if not event_id or event_id.group(1) != "22":
        continue

    query = get_data(event, "QueryName")

    if not query:
        continue

    count += 1

    print("=" * 80)
    print(f"DNS EVENT #{count}")
    print("=" * 80)
    print("UtcTime   :", get_data(event, "UtcTime"))
    print("ProcessId :", get_data(event, "ProcessId"))
    print("Image     :", get_data(event, "Image"))
    print("QueryName :", query)
    print()