import Evtx.Evtx as evtx
import mmap
import contextlib
import os

path = "Microsoft-Windows-Sysmon%4Operational.evtx"
output = "_sysmon_records.xml"

size = os.path.getsize(path)

records = []
chunks = 0

print("[+] Membaca:", path)
print("[+] Ukuran :", size, "bytes")
print()

with open(path, "rb") as f:

    with contextlib.closing(
        mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    ) as buf:

        # EVTX header pertama berukuran 0x1000
        offset = 0x1000

        # Setiap chunk EVTX berukuran 0x10000
        while offset + 0x10000 <= size:

            # Cek signature EVTX chunk
            if buf[offset:offset + 8] == b"ElfChnk\x00":

                chunks += 1

                try:

                    chunk = evtx.ChunkHeader(buf, offset)

                    count = 0

                    for record in chunk.records():
                        records.append(record.xml())
                        count += 1

                    print(
                        f"[+] Chunk {chunks} "
                        f"@ 0x{offset:X}: "
                        f"{count} records"
                    )

                except Exception as e:

                    print(
                        f"[!] Chunk {chunks} gagal: {e}"
                    )

            offset += 0x10000


print()
print("[+] Total records:", len(records))


# Simpan seluruh record sebagai XML/text
with open(output, "w", encoding="utf-8") as f:
    f.write("\n".join(records))


print("[+] Output:", output)
print("[+] Selesai.")