#include <Windows.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <libdfi.hpp>
#include <magic_enum.hpp>
#include <string>

template<typename Function>
inline auto LazyLoad(HMODULE library, const std::string& procName) {
    return (library) ? reinterpret_cast<Function*>(GetProcAddress(library, procName.data())) : nullptr;
}
#define LAZY_LOAD_PROC(LIBRARY, PROC) \
    auto lazy_##PROC{ LazyLoad<decltype(PROC)>(LIBRARY, #PROC) };

size_t scanCount{ 0 };

DFICallbackResult __cdecl PreScanError(void* user_data, const DFIScanInfoPre* info) {
    scanCount++;

    std::cout << std::endl;
    if ((*info)->path_in_archive) {
        std::wcout << L"Path in archive: " << *((*info)->path_in_archive) << std::endl;
    }
    std::cout << "Pre scan error: " << magic_enum::enum_name((*info)->scan_result) << std::endl;
    return DFICallbackResult::Success;
}

DFICallbackResult __cdecl PreScanCompletion(void* user_data, const DFIScanInfoPre* info) {
    scanCount++;

    std::cout << std::endl;
    if ((*info)->path_in_archive) {
        std::wcout << L"Path in archive: " << *((*info)->path_in_archive) << std::endl;
    }
    std::cout << "File type: " << magic_enum::enum_name((*info)->file_type) << std::endl;
    return DFICallbackResult::Success;
}

DFICallbackResult __cdecl ScanCompletion(void* user_data, const DFIScanInfoPost* info) {
    scanCount--;

    if (!scanCount) {
        std::cout << std::endl
                  << "Scan completed!" << std::endl;
    }
    std::cout << "Result!" << std::endl;
    std::cout << "  Verdict   : " << magic_enum::enum_name((*info)->verdict) << std::endl;
    auto score{ (*info)->score };
    std::cout << "  Score     : " << ((score == std::numeric_limits<double>::infinity()) ? "infinite" : std::to_string(score)) << std::endl;
    if ((*info)->indicators) {
        std::cout << "  Indicators: " << (*info)->indicators << std::endl;
    }
    if ((*info)->features) {
        std::cout << "  Features  : " << (*info)->features << std::endl;
    }
    return DFICallbackResult::Success;
}

DFICallbackResult __cdecl ScanError(void* user_data, DFIScanResult result) {
    scanCount--;

    std::cout << "Error: " << magic_enum::enum_name(result) << std::endl;
    return DFICallbackResult::Success;
}

void MyLogger(uint32_t level, wchar_t* message) {
    std::wcout << L"> Log (" << level << "): " << message << std::endl;
}

std::string ReadFile(std::filesystem::path path) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    const auto size{ std::filesystem::file_size(path) };
    std::string result(size, '\0');
    file.read(result.data(), size);
    return result;
}

void ScanFile(HMODULE ai, std::string& sample) {
    LAZY_LOAD_PROC(ai, dfi_cleanup);
    LAZY_LOAD_PROC(ai, dfi_delete_scan_arguments);
    LAZY_LOAD_PROC(ai, dfi_get_max_features_count);
    LAZY_LOAD_PROC(ai, dfi_get_telemetry);
    LAZY_LOAD_PROC(ai, dfi_get_version);
    LAZY_LOAD_PROC(ai, dfi_init);
    LAZY_LOAD_PROC(ai, dfi_init_scan_arguments);
    LAZY_LOAD_PROC(ai, dfi_scan);
    LAZY_LOAD_PROC(ai, dfi_set_features);
    LAZY_LOAD_PROC(ai, dfi_set_indicators);
    LAZY_LOAD_PROC(ai, dfi_set_max_scan_depth);
    LAZY_LOAD_PROC(ai, dfi_set_scan_archives);
    LAZY_LOAD_PROC(ai, dfi_set_scan_everything);
    LAZY_LOAD_PROC(ai, dfi_set_stop_scan_threshold);

    // Show some basic info about the model library
    char* version;
    char* build;
    lazy_dfi_get_version(&version, &build);
    std::cout << "Version: " << version << std::endl;
    std::cout << "Build  : " << build << std::endl;

    // Initialize the SDK and scan args
    auto status{ lazy_dfi_init(nullptr) };
    DFIScanArguments* args{ nullptr };
    status = lazy_dfi_init_scan_arguments(&args);

    // Set some scan args
    uint32_t count{ 0 };
    status = lazy_dfi_get_max_features_count(&count);
    std::vector<char> features(count * 8, '\0');
    status = lazy_dfi_set_features(args, features.size(), features.data());
    std::vector<char> indicators(512, '\0');
    status = lazy_dfi_set_indicators(args, indicators.size(), indicators.data());
    status = lazy_dfi_set_scan_archives(args, true);
    status = lazy_dfi_set_scan_everything(args, true);

    // Do a scan it. Multiple scan can be done between the a dfi_init and a dfi_cleanup
    status = lazy_dfi_scan(sample.data(), sample.size(), nullptr, PreScanError, PreScanCompletion, ScanCompletion, ScanError, args);

    // Gather telemetry about all scans that were done
    // This is done after a dfi_init and before a dfi_cleanup
    std::cout << std::endl;
    size_t bufferSize{ 0x500 };
    DFIErrorCode code;
    std::vector<char> telemetry;
    do {
        telemetry = std::vector<char>(bufferSize, 0);
        code = lazy_dfi_get_telemetry(telemetry.data(), bufferSize);
        bufferSize *= 2;
    } while (code == DFIErrorCode::InvalidParameter);
    if (code == DFIErrorCode::Success) {
        std::cout << "Scan telemetry: " << std::endl
                  << telemetry.data() << std::endl;
    } else {
        std::cout << "Scan telemetry error: " << (int)code << std::endl;
    }

    // Clear all data about the scans
    lazy_dfi_delete_scan_arguments(args);
    lazy_dfi_cleanup();
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 2) {
        auto ai{ LoadLibraryW(argv[1]) };
        if (ai) {
            std::string sample;
            try {
                sample = ReadFile(argv[2]);
                std::wcout << L"File -> " << argv[2] << std::endl;
            } catch (...) {
                std::cout << "Could not read sample file." << std::endl;
            }
            ScanFile(ai, sample);
            FreeLibrary(ai);
        }
    } else {
        std::wcout << argv[0] << L" <path to SentinelStaticAI.dll> <path to file>" << std::endl;
    }
}