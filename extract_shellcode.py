import pefile
import sys

def save_raw_shellcode(exe_path, bin_path):
    try:
        pe = pefile.PE(exe_path)
        target_section = None
        for section in pe.sections:
            if b".inject" in section.Name:
                target_section = section
                break

        if not target_section:
            print("[-] Could not find .inject section!")
            return

        raw_code = target_section.get_data()[: target_section.Misc_VirtualSize]

        with open(bin_path, "wb") as f:
            f.write(raw_code)

        print(f"[+] Successfully extracted {len(raw_code)} bytes to {bin_path}")

    except Exception as e:
        print(f"[-] Error: {e}")


if __name__ == "__main__":
    save_raw_shellcode("injector.exe", sys.argv[1])
