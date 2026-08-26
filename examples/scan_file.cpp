#define NOMINMAX
#include <Windows.h>

#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <libdfi.hpp>
#include <magic_enum.hpp>
#include <nlohmann/json.hpp>
#include <string>
#include <vector>

HMODULE ai{ nullptr };

template<typename Function>
inline auto LazyLoad(HMODULE library, const std::string& procName) {
    return (library) ? reinterpret_cast<Function*>(GetProcAddress(library, procName.data())) : nullptr;
}

template<typename ReturnType, typename... ArgTypes>
inline auto LazyLoadWithType(HMODULE library, const std::string& procedureName) noexcept {
    return LazyLoad<ReturnType(ArgTypes...)>(library, procedureName);
}

#define LAZY_LOAD_PROC(LIBRARY, PROC) \
    auto lazy_##PROC{ LazyLoad<decltype(PROC)>(LIBRARY, #PROC) };

DFICallbackResult __cdecl PreScanError(void* userData, const DFIScanInfoPre* info) {
    std::cout << std::endl;
    if (info && *info) {
        LAZY_LOAD_PROC(ai, dfi_get_path_in_archive);
        if (lazy_dfi_get_path_in_archive) {
            uint32_t pathSize;
            wchar_t* pathInArchive;
            if (lazy_dfi_get_path_in_archive((DFI**)info, &pathSize, &pathInArchive) == DFIErrorCode::Success && pathSize && pathInArchive) {
                std::wcout << L"Path in archive: " << pathInArchive << std::endl;
            }
        }
        std::cout << "Pre scan error!" << std::endl;
    }
    return DFICallbackResult::Success;
}

DFICallbackResult __cdecl PreScanCompletion(void* userData, const DFIScanInfoPre* info) {
    std::cout << std::endl;
    if (info && *info) {
        LAZY_LOAD_PROC(ai, dfi_get_file_type);
        LAZY_LOAD_PROC(ai, dfi_get_path_in_archive);
        if (lazy_dfi_get_path_in_archive) {
            uint32_t pathSize;
            wchar_t* pathInArchive;
            if (lazy_dfi_get_path_in_archive((DFI**)info, &pathSize, &pathInArchive) == DFIErrorCode::Success && pathSize && pathInArchive) {
                std::wcout << L"Path in archive: " << pathInArchive << std::endl;
            }
        }
        if (lazy_dfi_get_file_type) {
            AIFileType fileType;
            if (lazy_dfi_get_file_type((DFI**)info, &fileType) == DFIErrorCode::Success) {
                std::cout << "File type: " << magic_enum::enum_name(fileType) << std::endl;
            }
        }
    }
    return DFICallbackResult::Success;
}

DFICallbackResult __cdecl ScanCompletion(void* userData, const DFIScanInfoPost* info) {
    if (ai && info && *info) {
        LAZY_LOAD_PROC(ai, dfi_get_features);
        LAZY_LOAD_PROC(ai, dfi_get_indicators);
        LAZY_LOAD_PROC(ai, dfi_get_score);
        LAZY_LOAD_PROC(ai, dfi_get_verdict);
        if (lazy_dfi_get_verdict) {
            Verdict verdict;
            if (lazy_dfi_get_verdict((DFI**)info, &verdict) == DFIErrorCode::Success) {
                std::cout << "  Verdict   : " << magic_enum::enum_name(verdict) << std::endl;
            }
        }
        if (lazy_dfi_get_score) {
            double score;
            if (lazy_dfi_get_score((DFI**)info, &score) == DFIErrorCode::Success) {
                std::cout << "  Score     : "
                          << ((score == std::numeric_limits<double>::infinity()) ? "infinite" : std::to_string(score))
                          << std::endl;
            }
        }
        if (lazy_dfi_get_features) {
            uint32_t featureSize;
            char* features;
            if (lazy_dfi_get_features((DFI**)info, &featureSize, &features) == DFIErrorCode::Success) {
                std::cout << "  Features  : " << features << std::endl;
            }
        }
        if (lazy_dfi_get_indicators) {
            uint32_t indicatorsSize;
            char* indicators;
            if (lazy_dfi_get_indicators((DFI**)info, &indicatorsSize, &indicators) == DFIErrorCode::Success) {
                std::cout << "  Indicators: " << indicators << std::endl;
            }
        
        }
    }
    return DFICallbackResult::Success;
}

DFICallbackResult __cdecl ScanError(void* userData, DFIScanResult result) {
    std::cout << "Error: " << magic_enum::enum_name(result) << std::endl;
    return DFICallbackResult::Success;
}

void MyLogger(uint32_t level, wchar_t* message) {
    std::wcout << L"> Log (" << level << "): " << message << std::endl;
}

std::string ReadFile(const std::filesystem::path& path) {
    std::ifstream file(path, std::ios::in | std::ios::binary);
    const auto size{ std::filesystem::file_size(path) };
    std::string result(size, '\0');
    file.read(result.data(), size);
    return result;
}

void ScanFile(std::string& sample) {
    LAZY_LOAD_PROC(ai, dfi_cleanup);
    LAZY_LOAD_PROC(ai, dfi_delete_scan_arguments);
    LAZY_LOAD_PROC(ai, dfi_delete_scan_context);
    LAZY_LOAD_PROC(ai, dfi_find_file_type);
    LAZY_LOAD_PROC(ai, dfi_get_api_version);
    LAZY_LOAD_PROC(ai, dfi_get_max_features_count);
    LAZY_LOAD_PROC(ai, dfi_get_scan_results);
    LAZY_LOAD_PROC(ai, dfi_get_telemetry);
    LAZY_LOAD_PROC(ai, dfi_get_version);
    LAZY_LOAD_PROC(ai, dfi_init);
    LAZY_LOAD_PROC(ai, dfi_init_scan_arguments);
    LAZY_LOAD_PROC(ai, dfi_init_scan_context);
    LAZY_LOAD_PROC(ai, dfi_set_data);
    LAZY_LOAD_PROC(ai, dfi_set_features);
    LAZY_LOAD_PROC(ai, dfi_set_indicators);
    LAZY_LOAD_PROC(ai, dfi_set_scan_archives);
    LAZY_LOAD_PROC(ai, dfi_set_scan_everything);

    // Show some basic info about the model library and file to scan
    char* apiVersion{ nullptr };
    char* version{ nullptr };
    char* build{ nullptr };
    (void)lazy_dfi_get_version(&version, &build);
    std::cout << "Version: " << (version ? version : "<none>") << std::endl;
    std::cout << "Build: " << (build ? build : "<none>") << std::endl;
    bool dfiUsesScanContext{ false };
    if (lazy_dfi_get_api_version) {
        (void)lazy_dfi_get_api_version(&apiVersion);
        std::cout << "API version: " << (apiVersion ? apiVersion : "<none>") << std::endl;
        auto apiVersionStr{ std::string(apiVersion) };
        if (std::stoi(std::string(apiVersionStr.substr(0, apiVersionStr.find('.')))) >= 7 && lazy_dfi_init_scan_context) {
            dfiUsesScanContext = true;
        }
    }
    if (lazy_dfi_find_file_type) {
        AIFileType fileType;
        if (lazy_dfi_find_file_type(sample.data(), sample.size(), &fileType) == DFIErrorCode::Success) {
            std::cout << "File type: " << magic_enum::enum_name(fileType) << std::endl;
        }
    }

    // Initialize the SDK and scan args
    auto status{ lazy_dfi_init(nullptr, nullptr, 0) };
    DFIScanContext* context{ nullptr };
    if (dfiUsesScanContext) {
        lazy_dfi_init_scan_context(&context);
    } else {
        lazy_dfi_init_scan_arguments(&context);
    }

    // Set some scan args
    if (lazy_dfi_set_scan_archives) {
        lazy_dfi_set_scan_archives(context, true);
    }
    if (lazy_dfi_set_scan_everything) {
        lazy_dfi_set_scan_everything(context, true);
    }
    if (lazy_dfi_set_data) {
        lazy_dfi_set_data(context, sample.data(), sample.size());
    }
    if (lazy_dfi_get_max_features_count && lazy_dfi_set_features && lazy_dfi_set_indicators) {
        uint32_t maxFeaturesCount;
        if (lazy_dfi_get_max_features_count(&maxFeaturesCount) == DFIErrorCode::Success) {
            uint32_t featureSize{ 0 };
            auto features{ (char*)std::malloc(maxFeaturesCount * 8) };
            std::memset(features, '\0', maxFeaturesCount * 8);
            (void)lazy_dfi_set_features(context, maxFeaturesCount, features);
            auto indicators{ (char*)std::malloc(maxFeaturesCount * 8) };
            std::memset(indicators, '\0', maxFeaturesCount * 8);
            (void)lazy_dfi_set_indicators(context, maxFeaturesCount, indicators);
        }
    }

    // Do a scan it. Multiple scan can be done between the a dfi_init and a dfi_cleanup
    if (dfiUsesScanContext) {
        auto lazy_dfi_scan{ LazyLoadWithType<uint32_t, void*>(ai, "dfi_scan") };
        (void)lazy_dfi_scan(context);
    } else {
        auto lazy_dfi_scan{ LazyLoadWithType<uint32_t, void*, uint32_t, void*, void*, void*, void*, void*, void*>(ai, "dfi_scan") };
        (void)lazy_dfi_scan(sample.data(), sample.size(), nullptr, PreScanError, PreScanCompletion, ScanCompletion, ScanError, context);
    }

    // Gather telemetry about all scans that were done
    // This is done after a dfi_init and before a dfi_cleanup
    if (lazy_dfi_get_scan_results) {
        char* results{ nullptr };
        uint32_t length{ 0 };
        lazy_dfi_get_scan_results(context, &results, &length);
        const auto json{ nlohmann::json::parse(results, nullptr, false) };
        if (!json.is_discarded()) {
            std::cout << std::endl << "Result JSON:" << std::endl << json.dump(2) << std::endl;
        }
    }
    if (lazy_dfi_get_telemetry) {
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
            const auto json{ nlohmann::json::parse(telemetry.data(), nullptr, false) };
            if (!json.is_discarded()) {
                std::cout << "Scan telemetry:" << std::endl << json.dump(2) << std::endl;
            } else {
                std::cout << "Scan telemetry: " << std::endl << telemetry.data() << std::endl;
            }
        } else {
            std::cout << "Scan telemetry error: " << (int)code << std::endl;
        }
    }

    // Clear all data about the scans
    if (dfiUsesScanContext) {
        lazy_dfi_delete_scan_context(&context);
    } else {
        lazy_dfi_delete_scan_arguments(context);
    }
    lazy_dfi_cleanup();
}

int wmain(int argc, wchar_t** argv) {
    if (argc > 2) {
        ai = LoadLibraryW(argv[1]);
        if (ai) {
            std::string sample;
            try {
                sample = ReadFile(argv[2]);
                std::wcout << L"File -> " << argv[2] << std::endl;
            } catch (...) {
                std::cout << "Could not read sample file." << std::endl;
            }
            ScanFile(sample);
            FreeLibrary(ai);
        }
    } else {
        std::wcout << argv[0] << L" <path to SentinelStaticAI.dll> <path to file>" << std::endl;
    }
    return 0;
}
