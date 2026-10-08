import re

XML_FILE = "_sysmon_records.xml"


def get_data(event, name):
    pattern = r'Name="' + re.escape(name) + r'">(.*?)</Data>'
    match = re.search(pattern, event, re.DOTALL)
    return match.group(1).strip() if match else ""


with open(XML_FILE, "r", encoding="utf-8") as f:
    records = f.read().split("<Event ")


count = 0

for event in records:

    event_id = re.search(
        r"<EventID[^>]*>(\d+)</EventID>",
        event
    )

    if not event_id or event_id.group(1) != "1":
        continue

    command_line = get_data(event, "CommandLine")

    if "schtasks" not in command_line.lower():
        continue

    if "/create" not in command_line.lower():
        continue

    count += 1

    print("=" * 80)
    print(f"EVENT #{count}")
    print("=" * 80)
    print("UtcTime     :", get_data(event, "UtcTime"))
    print("ProcessId   :", get_data(event, "ProcessId"))
    print("Image       :", get_data(event, "Image"))
    print("CommandLine :", command_line)
    print()


print("=" * 80)
print("TOTAL:", count)
print("=" * 80)
