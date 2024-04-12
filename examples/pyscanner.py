import binascii
import pydfi
import sys

if len(sys.argv) < 3:
    print('{} <path to SentinelStaticAI.dll> <path to file>'.format(sys.argv[0]))
    sys.exit()

scanCount = 0

def MyLogger(level: int, message: str) -> None:
    print("> Log({}): {}".format(level, message))

def MyPreScanError(userData: str, info: pydfi.Dfi) -> bool:
    global scanCount
    scanCount += 1

    print()
    pathInArchive = info.path_in_archive
    if len(pathInArchive):
        print("Path in archive: {}".format(pathInArchive))
    return True

def MyPreScanCompletion(userData: str, info: pydfi.Dfi) -> bool:
    global scanCount
    scanCount += 1
    
    print()
    pathInArchive = info.path_in_archive
    if len(pathInArchive):
        print("Path in archive: {}".format(pathInArchive))
    print("File type: {}".format(info.file_type))
    return True

def MyScanCompletion(userData: str, info: pydfi.Dfi) -> bool:
    global scanCount
    scanCount -= 1
    
    if (scanCount == 0):
        print("\nScan completed!")
        
    print("  Verdict   : {}".format(info.verdict))
    print("  Score     : {}".format("infinite" if info.score == float("inf") else info.score))
    indicators = info.indicators
    if (len(indicators)):
        print("  Indicators: {}".format(indicators))
    features = info.features
    if (len(features)):
        print("  Features  : {}...".format(binascii.hexlify(features[0:16]).decode()))
    return True

def MyScanError(userData: str, result: int) -> bool:
    global scanCount
    scanCount -= 1
    
    print("Error: {}".format(result))
    return True

pydfi.load_ai(sys.argv[1])
print("Version: {}, Build: {}".format(*pydfi.version()))

# Initialize DFI and setup arguments for scanning data
pydfi.init(MyLogger)
args = pydfi.ScanArguments()
args.scan_archives = True
args.scan_everything = True

# Scan user supplied data. This can be done multiple times
data = open(sys.argv[2], "rb").read()
pydfi.Scan(data, "", MyPreScanError, MyPreScanCompletion, MyScanCompletion, MyScanError, args)

# Show telemetry for all scans that were done
# Done it a try block because the telemetry is not supported on old versions of DFI
try: print("\nScan telemetry: {}".format(pydfi.telemetry()))
except: pass

# Must be called at end or else the process will hang
pydfi.cleanup()