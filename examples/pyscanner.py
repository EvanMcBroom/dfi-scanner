import binascii
import json
import pydfi
import sys

if len(sys.argv) != 3:
    print(f"{sys.argv[0]} <path to SentinelStaticAI.dll> <path to file>")
    sys.exit()

def MyLogger(level: int, message: str) -> None:
    safe_message = message.encode("ascii", errors="backslashreplace").decode("ascii")
    print(f"> Log({level}): {safe_message}")

def MyPreScanError(userData: str, info: pydfi.Dfi) -> bool:
    print()
    pathInArchive = info.path_in_archive
    if len(pathInArchive):
        print(f"Path in archive: {pathInArchive}")
    return True

def MyPreScanCompletion(userData: str, info: pydfi.Dfi) -> bool:
    print()
    pathInArchive = info.path_in_archive
    if len(pathInArchive):
        print(f"Path in archive: {pathInArchive}")
    print(f"File type: {info.file_type}")
    return True


def MyScanCompletion(userData: str, info: pydfi.Dfi) -> bool:
    print(f"  Verdict   : {info.verdict}")
    print(f"  Score     : {'infinite' if info.score == float('inf') else info.score}")
    indicators = info.indicators
    if indicators:
        print(f"  Indicators: {indicators}")
    features = info.features
    if features:
        print(f"  Features  : {binascii.hexlify(features[:16]).decode()}...")
    return True

def MyScanError(userData: str, result: int) -> bool:
    print(f"Error: {result}")
    return True

if not pydfi.load_ai(sys.argv[1]):
    raise RuntimeError("The DLL does not provide a supported DFI API.")

print("Version: {}, Build: {}".format(*pydfi.version()))
usesContextApi = pydfi.uses_scan_context()
try:
    api_version = pydfi.api_version()
    print(f"API version: {api_version}")
except pydfi.DfiException:
    pass

# Initialize DFI
pydfi.init(MyLogger)
try:
    # Setup arguments for scanning data
    args = pydfi.ScanArguments()
    if not usesContextApi:
        args.scan_archives = True
        args.scan_everything = True

    # Scan user supplied data. This can be done multiple times
    with open(sys.argv[2], "rb") as sample_file:
        data = sample_file.read()
    scan = pydfi.Scan(data, "", MyPreScanError, MyPreScanCompletion, MyScanCompletion, MyScanError, args)

    # Show scan results
    if usesContextApi:
        if scan.scan_results:
            print("Result JSON:")
            print(json.dumps(json.loads(scan.scan_results), indent=2))
        else:
            print("Result JSON: <none>")

    # Show telemetry for all scans that were done
    # Done it a try block because the telemetry is not supported on old versions of DFI
    try: print(f"\nScan telemetry: {pydfi.telemetry()}")
    except pydfi.DfiException: pass
finally:
    # Must be called at end or else the process will hang
    pydfi.cleanup()