# Deep File Inspection

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg?style=flat)](LICENSE.txt)

Deep File Inspection (DFI) is a feature of SentinelOne that allows it to scan files at rest.
DFI contains two of the three detection technologies used by SentinelOne agents on endpoint devices.
The three detection technologies include their "reputation" engine (e.g, file hashes), StaticAI (e.g., machine learning), and "ActiveEDR" (e.g., realtime telemetry from user-mode processes).
DFI implements all of StaticAI and some if not all of the reputation engine.
Windows installations of SentinelOne also include an AMSI provider which may be considered part of the reputation engine as well.

DFI exposes a private API for SentinelOne to use but there also exists a simpler public wrapper API that SentinelOne sells licenses for, named the "Nexus API."
The Nexus API is what VirusTotal uses to scan a file with SentinelOne.
This repo documents the DFI API to allow it to be used directly instead of using the Nexus API.

The private DFI API is exposed by the `SentinelStaticAI.dll` binary that ships with any SentinelOne installation.
Unlike the Nexus API, the DFI API can be used without a license.
It can also be used without Internet access as it only uses a self-contained ML model, Yara signatures, and other detections that are packaged into its PE resources or its `.rdata` section.

The `SentinelStaticAI.dll` binary has two version numbers, a file version and an internal API [semantic version](https://semver.org/).
Its file version increased to at least `24.x.x.x` before starting over.
Its API version is queriable via an export starting in version `6.0.0` and is the only reliable method to assess compatibility with this project.
This project has been tested with API major versions 6 and 7.
Your mileage may vary with other API versions.

## Building

The project uses [CMake](https://cmake.org/) to generate and run the build system files for your platform.
The project does not rely on any library manager to allow it to be easily built in an offline environment if desired.

```
git clone --recurse-submodules https://github.com/EvanMcBroom/dfi-scanner.git
cd dfi-scanner/builds
cmake .. -A {Win32 | x64}
cmake --build .
```

By default CMake will build a `libdfi32` or `libdfi64` library with equivalent functionality to the Nexus API.
There is a `libdfi.hpp` file that may be used as the SDK for the library.
The `examples` directory demonstrates how to use the library.
CMake will also build a `pydfi` Python module to allow for easy access to the API.

## Running

If you have a licensed copy of SentinelOne, the `SentinelStaticAI.dll` binary will be in its installation directory.
You may use it with the example C program like so:

```bash
scan_file.exe <path to SentinelStaticAI.dll> <path to file>
```
For the Python script, first copy the built `*.pyd` file to the same directory as the script, then you may use it like so:

```bash
python pyscanner.py <path to SentinelStaticAI.dll> <path to file>
```