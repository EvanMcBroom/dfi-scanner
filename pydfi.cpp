#define NOMINMAX
#include <Windows.h>
#include <codecvt>
#include <limits>
#include <locale>
#include <magic_enum.hpp>
#include <pybind11/functional.h>
#include <pybind11/stl.h>
#include <pydfi.hpp>
#include <string>

#include <iostream>

#define PYDFI_AI_NOT_LOADED_STR "AI not loaded."
#define PYDFI_UNSUPPORTED_METHOD_STR "Method not supported by this version of DFI."

namespace py = pybind11;

using ScanArgumentsFn = decltype(static_cast<DFIErrorCode (*)(
    const char*, uint32_t, void*, PreCallback, PreCallback,
    PostCallback, ErrorCallback, DFIScanArguments*)>(dfi_scan));
using ScanContextFn = decltype(static_cast<DFIErrorCode (*)(DFIScanContext*)>(dfi_scan));

template<typename Function>
inline auto LazyLoad(HMODULE library, const std::string& procName) {
    return (library) ? reinterpret_cast<Function*>(GetProcAddress(library, procName.data())) : nullptr;
}
#define LAZY_LOAD_PROC(LIBRARY, PROC) \
    (lazy_##PROC = LazyLoad<decltype(PROC)>(reinterpret_cast<HMODULE>(LIBRARY), #PROC))

namespace {
    void* ai{ nullptr };
    decltype(dfi_cleanup)* lazy_dfi_cleanup;
    decltype(dfi_delete_scan_arguments)* lazy_dfi_delete_scan_arguments;
    decltype(dfi_delete_scan_context)* lazy_dfi_delete_scan_context;
    decltype(dfi_find_file_type)* lazy_dfi_find_file_type;
    decltype(dfi_get_api_version)* lazy_dfi_get_api_version;
    decltype(dfi_get_depth)* lazy_dfi_get_depth;
    decltype(dfi_get_features)* lazy_dfi_get_features;
    decltype(dfi_get_file_data)* lazy_dfi_get_file_data;
    decltype(dfi_get_file_type)* lazy_dfi_get_file_type;
    decltype(dfi_get_indicators)* lazy_dfi_get_indicators;
    decltype(dfi_get_macro_content)* lazy_dfi_get_macro_content;
    decltype(dfi_get_max_features_count)* lazy_dfi_get_max_features_count;
    decltype(dfi_get_path_in_archive)* lazy_dfi_get_path_in_archive;
    decltype(dfi_get_score)* lazy_dfi_get_score;
    decltype(dfi_get_scan_results)* lazy_dfi_get_scan_results;
    decltype(dfi_get_sha1)* lazy_dfi_get_sha1;
    decltype(dfi_get_sha256)* lazy_dfi_get_sha256;
    decltype(dfi_get_telemetry)* lazy_dfi_get_telemetry;
    decltype(dfi_get_verdict)* lazy_dfi_get_verdict;
    decltype(dfi_get_version)* lazy_dfi_get_version;
    decltype(dfi_init)* lazy_dfi_init;
    decltype(dfi_init_scan_arguments)* lazy_dfi_init_scan_arguments;
    decltype(dfi_init_scan_context)* lazy_dfi_init_scan_context;
    decltype(dfi_is_archive)* lazy_dfi_is_archive;
    decltype(dfi_reset_custom_yara_rules)* lazy_dfi_reset_custom_yara_rules;
    decltype(dfi_reset_detection_yara_rules)* lazy_dfi_reset_detection_yara_rules;
    ScanArgumentsFn lazy_dfi_scan_arguments;
    ScanContextFn lazy_dfi_scan_context;
    decltype(dfi_set_custom_yara_rules)* lazy_dfi_set_custom_yara_rules;
    decltype(dfi_set_allowed_inner_file_types)* lazy_dfi_set_allowed_inner_file_types;
    decltype(dfi_set_data)* lazy_dfi_set_data;
    decltype(dfi_set_detection_yara_rules)* lazy_dfi_set_detection_yara_rules;
    decltype(dfi_set_features)* lazy_dfi_set_features;
    decltype(dfi_set_file_type)* lazy_dfi_set_file_type;
    decltype(dfi_set_hash_limits)* lazy_dfi_set_hash_limits;
    decltype(dfi_set_indicators)* lazy_dfi_set_indicators;
    decltype(dfi_set_macro_content)* lazy_dfi_set_macro_content;
    decltype(dfi_set_max_scan_depth)* lazy_dfi_set_max_scan_depth;
    decltype(dfi_set_max_archive_entry_size)* lazy_dfi_set_max_archive_entry_size;
    decltype(dfi_set_max_archive_inner_files)* lazy_dfi_set_max_archive_inner_files;
    decltype(dfi_set_msi_scan)* lazy_dfi_set_msi_scan;
    decltype(dfi_set_scan_archives)* lazy_dfi_set_scan_archives;
    decltype(dfi_set_scan_everything)* lazy_dfi_set_scan_everything;
    decltype(dfi_set_stop_scan_threshold)* lazy_dfi_set_stop_scan_threshold;
    decltype(dfi_validate_config)* lazy_dfi_validate_config;
    bool usesScanContextApi{ false };
    PyDfi::Logger userLogger{ nullptr };
    auto utfConverter{ std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>>() };

    void ToCppLogger(uint32_t level, wchar_t* message) {
        if (userLogger) {
            userLogger(level, utfConverter.to_bytes(message));
        }
    }
}

namespace PyDfi {
    Dfi::Dfi(DFI** dfi)
        : dfi(dfi) {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
    }

    uint32_t Dfi::GetDepth() {
        if (!lazy_dfi_get_depth) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        uint32_t depth{ 0 };
        auto error{ lazy_dfi_get_depth(dfi, &depth) };
        if (error == DFIErrorCode::Success) {
            return depth;
        }
        throw Exception(error);
    }

    py::bytes Dfi::GetFeatures() {
        if (!lazy_dfi_get_features) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        uint32_t featuresSize{ 0 };
        char* features{ 0 };
        auto error{ lazy_dfi_get_features(dfi, &featuresSize, &features) };
        return (error == DFIErrorCode::Success && featuresSize) ? py::bytes(features, featuresSize) : py::bytes();
    }

    py::bytes Dfi::GetFileData() {
        if (!lazy_dfi_get_file_data) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        uint32_t dataSize{ 0 };
        char* data{ 0 };
        auto error{ lazy_dfi_get_file_data(dfi, &dataSize, &data) };
        return (error == DFIErrorCode::Success && dataSize) ? py::bytes(data, dataSize) : py::bytes();
    }

    AIFileType Dfi::GetFileType() {
        if (!lazy_dfi_get_file_type) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        AIFileType type{ 0 };
        auto error{ lazy_dfi_get_file_type(dfi, &type) };
        if (error == DFIErrorCode::Success) {
            return type;
        }
        throw Exception(error);
    }

    std::string Dfi::GetIndicators() {
        if (!lazy_dfi_get_indicators) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        uint32_t indicatorsSize{ 0 };
        char* indicators{ 0 };
        auto error{ lazy_dfi_get_indicators(dfi, &indicatorsSize, &indicators) };
        return (error == DFIErrorCode::Success && indicatorsSize) ? py::bytes(indicators, indicatorsSize) : py::bytes();
    }

    py::bytes Dfi::GetMacroContent() {
        if (!lazy_dfi_get_macro_content) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        uint32_t contentSize{ 0 };
        char* content{ 0 };
        auto error{ lazy_dfi_get_macro_content(dfi, &contentSize, &content) };
        return (error == DFIErrorCode::Success && contentSize) ? py::bytes(content, contentSize) : py::bytes();
    }

    std::string Dfi::GetPathInArchive() {
        if (!lazy_dfi_get_path_in_archive) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        uint32_t pathSize{ 0 };
        wchar_t* path{ 0 };
        auto error{ lazy_dfi_get_path_in_archive(dfi, &pathSize, &path) };
        auto result{ (error == DFIErrorCode::Success && pathSize) ? std::wstring(path, path + pathSize) : std::wstring() };
        return utfConverter.to_bytes(result);
    }

    double Dfi::GetScore() {
        if (!lazy_dfi_get_score) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        double score{ 0 };
        auto error{ lazy_dfi_get_score(dfi, &score) };
        if (error == DFIErrorCode::Success) {
            return score;
        }
        throw Exception(error);
    }

    py::bytes Dfi::GetSha1() {
        if (!lazy_dfi_get_sha1) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        std::vector<char> sha1(20, '\0');
        lazy_dfi_get_sha1(dfi, sha1.data());
        return std::string(sha1.data(), sha1.data() + 20);
    }

    py::bytes Dfi::GetSha256() {
        if (!lazy_dfi_get_sha256) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        std::vector<char> sha256(32, '\0');
        lazy_dfi_get_sha256(dfi, sha256.data());
        return std::string(sha256.data(), sha256.data() + 32);
    }

    Verdict Dfi::GetVerdict() {
        if (!lazy_dfi_get_verdict) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        Verdict verdict{ 0 };
        auto error{ lazy_dfi_get_verdict(dfi, &verdict) };
        if (error == DFIErrorCode::Success) {
            return verdict;
        }
        throw Exception(error);
    }

    bool Dfi::IsArchive() {
        if (!lazy_dfi_is_archive) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        bool isArchive{ 0 };
        auto error{ lazy_dfi_is_archive(dfi, &isArchive) };
        if (error == DFIErrorCode::Success) {
            return isArchive;
        }
        throw Exception(error);
    }

    Exception::Exception(DFIErrorCode code)
        : message(magic_enum::enum_name(code)) {
    }

    Exception::Exception(const char* message)
        : message(message) {
    }

    const char* Exception::what() const noexcept {
        return (!message.empty()) ? message.data() : "Unknown error.";
    }

    ScanArguments::ScanArguments() {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        auto error{ usesScanContextApi ? lazy_dfi_init_scan_context(&args) : lazy_dfi_init_scan_arguments(&args) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
        if (!usesScanContextApi && lazy_dfi_get_max_features_count && lazy_dfi_set_features && lazy_dfi_set_indicators) {
            uint32_t maxFeaturesCount{ 0 };
            error = lazy_dfi_get_max_features_count(&maxFeaturesCount);
            if (error != DFIErrorCode::Success || maxFeaturesCount > std::numeric_limits<uint32_t>::max() / 8) {
                throw Exception(error);
            }
            userFeatures.assign(static_cast<size_t>(maxFeaturesCount) * 8, '\0');
            userIndicators.assign(512, '\0');
            error = lazy_dfi_set_features(args, static_cast<uint32_t>(userFeatures.size()), userFeatures.data());
            if (error == DFIErrorCode::Success) {
                error = lazy_dfi_set_indicators(args, static_cast<uint32_t>(userIndicators.size()), userIndicators.data());
            }
            if (error != DFIErrorCode::Success) {
                throw Exception(error);
            }
        }
    }

    ScanArguments::~ScanArguments() {
        // Ignore any error that may occur because
        // deconstructors should not throw.
        // Reference: C++ Core Guidelines
        if (args) {
            if (usesScanContextApi) {
                (void)lazy_dfi_delete_scan_context(&args);
            } else {
                (void)lazy_dfi_delete_scan_arguments(args);
            }
        }
    }

    void ScanArguments::SetAllowedInnerFileTypes(const std::vector<AIFileType>& fileTypes) {
        if (!lazy_dfi_set_allowed_inner_file_types) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        allowedInnerFileTypes = fileTypes;
        lazy_dfi_set_allowed_inner_file_types(args, allowedInnerFileTypes.data(), static_cast<uint32_t>(allowedInnerFileTypes.size()));
    }

    void ScanArguments::SetFeatures(const py::bytes& features) {
        if (!lazy_dfi_set_features) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        auto maxFeaturesCount{ GetMaxFeaturesCount() };
        std::string strFeatures{ features };
        if (strFeatures.size() < (maxFeaturesCount * 8)) {
            throw Exception("Feature size not large enough to support the max feature count that may be used.");
        }
        userFeatures = std::vector<char>(strFeatures.begin(), strFeatures.end());
        auto error{ lazy_dfi_set_features(args, userFeatures.size(), userFeatures.data()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetFileType(AIFileType fileType) {
        if (!lazy_dfi_set_file_type) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        lazy_dfi_set_file_type(args, fileType);
    }

    void ScanArguments::SetHashLimits(const std::array<uint64_t, 2>& hashLimits) {
        if (!lazy_dfi_set_hash_limits) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        this->hashLimits = hashLimits;
        auto error{ lazy_dfi_set_hash_limits(args, this->hashLimits.data()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetIndicators(const std::string& indicators) {
        if (!lazy_dfi_set_indicators) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        userIndicators = std::vector<char>(indicators.begin(), indicators.end());
        // Make sure the indicators buffer is at least 512 bytes which
        // is the required amount for the C API
        if (userIndicators.size() < 512) {
            userIndicators.resize(512, '\0');
        }
        auto error{ lazy_dfi_set_indicators(args, userIndicators.size(), userIndicators.data()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetMacroContent(const py::bytes& macroContent) {
        if (!lazy_dfi_set_macro_content) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        std::string strMacroContent{ macroContent };
        userMacroContent = std::vector<char>(strMacroContent.begin(), strMacroContent.end());
        auto error{ lazy_dfi_set_macro_content(args, userMacroContent.size(), userMacroContent.data()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetMaxArchiveEntrySize(uint32_t archiveEntrySize) {
        if (!lazy_dfi_set_max_archive_entry_size) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        auto error{ lazy_dfi_set_max_archive_entry_size(args, archiveEntrySize) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetMaxArchiveInnerFiles(uint32_t maxArchiveInnerFiles) {
        if (!lazy_dfi_set_max_archive_inner_files) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        lazy_dfi_set_max_archive_inner_files(args, maxArchiveInnerFiles);
    }

    void ScanArguments::SetMaxScanDepth(uint32_t scanDepth) {
        if (!lazy_dfi_set_max_scan_depth) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        auto error{ lazy_dfi_set_max_scan_depth(args, scanDepth) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetMsiScan(bool enable) {
        if (!lazy_dfi_set_msi_scan) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        lazy_dfi_set_msi_scan(args, enable);
    }

    void ScanArguments::SetScanArchives(bool enable) {
        if (!lazy_dfi_set_scan_archives) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        auto error{ lazy_dfi_set_scan_archives(args, enable) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetScanEverything(bool enable) {
        if (!lazy_dfi_set_scan_everything) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        auto error{ lazy_dfi_set_scan_everything(args, enable) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetStopScanThreshold(uint32_t stopScanThreshold) {
        if (!lazy_dfi_set_stop_scan_threshold) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        auto error{ lazy_dfi_set_stop_scan_threshold(args, stopScanThreshold) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    DFIScanArguments* ScanArguments::Ptr() {
        return args;
    }

    Scan::Scan(const py::bytes& data, const std::string& userData, PreCallback onPreScanError, PreCallback onPreScanCompletion, PostCallback onScanCompletion, ErrorCallback onScanError, const std::shared_ptr<ScanArguments>& args)
        : userData(userData), userPreScanCompletion(onPreScanCompletion), userPreScanError(onPreScanError), userScanCompletion(onScanCompletion), userScanError(onScanError), args(args) {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        std::string strData{ data };
        if (strData.size() > std::numeric_limits<uint32_t>::max()) {
            throw Exception("Data is too large for this version of the DFI scan API.");
        }
        scanData = std::vector<char>(strData.begin(), strData.end());
        wrappedUserData.scanThis = this;
        wrappedUserData.userData = &this->userData;
        DFIErrorCode error;
        if (usesScanContextApi) {
            if (!lazy_dfi_set_data || !lazy_dfi_scan_context || !lazy_dfi_get_scan_results) {
                throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
            }
            lazy_dfi_set_data(this->args->Ptr(), scanData.data(), scanData.size());
            error = lazy_dfi_scan_context(this->args->Ptr());
            if (error == DFIErrorCode::Success) {
                char* results{ nullptr };
                uint32_t length{ 0 };
                lazy_dfi_get_scan_results(this->args->Ptr(), &results, &length);
                if (results && length) {
                    scanResults.assign(results, length);
                }
            }
        } else {
            error = lazy_dfi_scan_arguments(scanData.data(), static_cast<uint32_t>(scanData.size()), &this->wrappedUserData,
                ToCppPreScanError, ToCppPreScanCompletion, ToCppScanCompletion, ToCppScanError, this->args->Ptr());
        }
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    std::string Scan::GetScanResults() const {
        return scanResults;
    }

    DFICallbackResult __cdecl Scan::ToCppPreScanCompletion(void* userData, const DFIScanInfoPre* info) {
        auto wrappedUserData{ reinterpret_cast<WrappedUserData*>(userData) };
        Dfi dfi((DFI**)(info));
        auto succeeded{ wrappedUserData->scanThis->userPreScanCompletion(*wrappedUserData->userData, dfi) };
        return (succeeded) ? DFICallbackResult::Success : (DFIErrorCode)-1;
    }

    DFICallbackResult __cdecl Scan::ToCppPreScanError(void* userData, const DFIScanInfoPre* info) {
        auto wrappedUserData{ reinterpret_cast<WrappedUserData*>(userData) };
        Dfi dfi((DFI**)(info));
        auto succeeded{ wrappedUserData->scanThis->userPreScanError(*wrappedUserData->userData, dfi) };
        return (succeeded) ? DFICallbackResult::Success : (DFIErrorCode)-1;
    }

    DFICallbackResult __cdecl Scan::ToCppScanCompletion(void* userData, const DFIScanInfoPost* info) {
        auto wrappedUserData{ reinterpret_cast<WrappedUserData*>(userData) };
        Dfi dfi((DFI**)(info));
        auto succeeded{ wrappedUserData->scanThis->userScanCompletion(*wrappedUserData->userData, dfi) };
        return (succeeded) ? DFICallbackResult::Success : (DFIErrorCode)-1;
    }

    DFICallbackResult __cdecl Scan::ToCppScanError(void* userData, DFIScanResult result) {
        auto wrappedUserData{ reinterpret_cast<WrappedUserData*>(userData) };
        auto succeeded{ wrappedUserData->scanThis->userScanError(*wrappedUserData->userData, result) };
        return (succeeded) ? DFICallbackResult::Success : (DFIErrorCode)-1;
    }

    void Cleanup() {
        if (!ai || !lazy_dfi_cleanup) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        userLogger = nullptr;
        auto error{ lazy_dfi_cleanup() };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    AIFileType FindFileType(const py::bytes& data) {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_find_file_type) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        std::string fileData{ data };
        AIFileType fileType{ AIFileType::Unknown };
        auto error{ lazy_dfi_find_file_type(fileData.data(), fileData.size(), &fileType) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
        return fileType;
    }

    std::string GetApiVersion() {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_get_api_version) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        char* version{ nullptr };
        auto error{ lazy_dfi_get_api_version(&version) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
        return version ? std::string(version) : std::string();
    }


    uint32_t GetMaxFeaturesCount() {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_get_max_features_count) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        uint32_t count{ 0 };
        // Will always succeed when given a valid pointer
        (void)lazy_dfi_get_max_features_count(&count);
        return count;
    }

    std::string GetTelemetry() {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_get_telemetry) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        size_t telemetrySize{ 0x500 };
        DFIErrorCode code;
        std::vector<char> telemetry;
        do {
            telemetry = std::vector<char>(telemetrySize, '\0');
            code = lazy_dfi_get_telemetry(telemetry.data(), telemetrySize);
            telemetrySize *= 2;
        } while (code == DFIErrorCode::InvalidParameter);
        return std::string(telemetry.data());
    }

    std::pair<Version, Build> GetVersion() {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_get_version) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        char* version;
        char* build;
        auto error{ lazy_dfi_get_version(&version, &build) };
        return ((error == DFIErrorCode::Success && version && build)) ? std::pair{ std::string(version), std::string(build) } : std::pair{ std::string(), std::string() };
    }

    bool LoadAi(const std::string& path) {
        std::wstring utf16Path{ utfConverter.from_bytes(path) };
        if (ai = LoadLibraryW(utf16Path.data())) {
            LAZY_LOAD_PROC(ai, dfi_cleanup);
            LAZY_LOAD_PROC(ai, dfi_delete_scan_arguments);
            LAZY_LOAD_PROC(ai, dfi_delete_scan_context);
            LAZY_LOAD_PROC(ai, dfi_find_file_type);
            LAZY_LOAD_PROC(ai, dfi_get_api_version);
            LAZY_LOAD_PROC(ai, dfi_get_depth);
            LAZY_LOAD_PROC(ai, dfi_get_features);
            LAZY_LOAD_PROC(ai, dfi_get_file_data);
            LAZY_LOAD_PROC(ai, dfi_get_file_type);
            LAZY_LOAD_PROC(ai, dfi_get_indicators);
            LAZY_LOAD_PROC(ai, dfi_get_macro_content);
            LAZY_LOAD_PROC(ai, dfi_get_max_features_count);
            LAZY_LOAD_PROC(ai, dfi_get_path_in_archive);
            LAZY_LOAD_PROC(ai, dfi_get_score);
            LAZY_LOAD_PROC(ai, dfi_get_scan_results);
            LAZY_LOAD_PROC(ai, dfi_get_sha1);
            LAZY_LOAD_PROC(ai, dfi_get_sha256);
            LAZY_LOAD_PROC(ai, dfi_get_telemetry);
            LAZY_LOAD_PROC(ai, dfi_get_verdict);
            LAZY_LOAD_PROC(ai, dfi_get_version);
            LAZY_LOAD_PROC(ai, dfi_init);
            LAZY_LOAD_PROC(ai, dfi_init_scan_arguments);
            LAZY_LOAD_PROC(ai, dfi_init_scan_context);
            LAZY_LOAD_PROC(ai, dfi_is_archive);
            LAZY_LOAD_PROC(ai, dfi_reset_custom_yara_rules);
            LAZY_LOAD_PROC(ai, dfi_reset_detection_yara_rules);
            lazy_dfi_scan_arguments = reinterpret_cast<ScanArgumentsFn>(GetProcAddress(reinterpret_cast<HMODULE>(ai), "dfi_scan"));
            lazy_dfi_scan_context = reinterpret_cast<ScanContextFn>(GetProcAddress(reinterpret_cast<HMODULE>(ai), "dfi_scan"));
            LAZY_LOAD_PROC(ai, dfi_set_allowed_inner_file_types);
            LAZY_LOAD_PROC(ai, dfi_set_custom_yara_rules);
            LAZY_LOAD_PROC(ai, dfi_set_data);
            LAZY_LOAD_PROC(ai, dfi_set_detection_yara_rules);
            LAZY_LOAD_PROC(ai, dfi_set_features);
            LAZY_LOAD_PROC(ai, dfi_set_file_type);
            LAZY_LOAD_PROC(ai, dfi_set_hash_limits);
            LAZY_LOAD_PROC(ai, dfi_set_indicators);
            LAZY_LOAD_PROC(ai, dfi_set_macro_content);
            LAZY_LOAD_PROC(ai, dfi_set_max_archive_entry_size);
            LAZY_LOAD_PROC(ai, dfi_set_max_archive_inner_files);
            LAZY_LOAD_PROC(ai, dfi_set_max_scan_depth);
            LAZY_LOAD_PROC(ai, dfi_set_msi_scan);
            LAZY_LOAD_PROC(ai, dfi_set_scan_archives);
            LAZY_LOAD_PROC(ai, dfi_set_scan_everything);
            LAZY_LOAD_PROC(ai, dfi_set_stop_scan_threshold);
            LAZY_LOAD_PROC(ai, dfi_validate_config);

            const auto supportsLegacyApi{ lazy_dfi_delete_scan_arguments && lazy_dfi_init_scan_arguments && lazy_dfi_scan_arguments };
            const auto supportsContextApi{ lazy_dfi_delete_scan_context && lazy_dfi_get_scan_results && lazy_dfi_init_scan_context && lazy_dfi_scan_context && lazy_dfi_set_data };
            usesScanContextApi = supportsContextApi;
            if (lazy_dfi_cleanup && lazy_dfi_get_version && lazy_dfi_init && (supportsLegacyApi || supportsContextApi)) {
                return true;
            }
            FreeLibrary(reinterpret_cast<HMODULE>(ai));
            ai = nullptr;
        }
        return false;
    }

    void Init(Logger logger) {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (logger) {
            userLogger = logger;
        }
        auto error{ lazy_dfi_init(ToCppLogger, nullptr, 0) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    bool UsesScanContext() {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        return usesScanContextApi;
    }

    void ResetCustomYaraRules() {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_reset_custom_yara_rules) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        // API is hardcoded to return DFIErrorCode::Success
        (void)lazy_dfi_reset_custom_yara_rules();
    }

    void ResetDetectionYaraRules() {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_reset_detection_yara_rules) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        auto error{ lazy_dfi_reset_detection_yara_rules() };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void SetCustomYaraRules(const py::bytes& yarc) {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_set_custom_yara_rules) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        bool isArchive{ 0 };
        std::string strYarc{ yarc };
        auto error{ lazy_dfi_set_custom_yara_rules(strYarc.data(), strYarc.size()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void SetDetectionYaraRules(const py::bytes& yarc) {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_set_detection_yara_rules) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        std::string rules{ yarc };
        auto error{ lazy_dfi_set_detection_yara_rules(rules.data(), rules.size()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ValidateConfig(const std::string& config) {
        if (!ai) {
            throw Exception(PYDFI_AI_NOT_LOADED_STR);
        }
        if (!lazy_dfi_validate_config) {
            throw Exception(PYDFI_UNSUPPORTED_METHOD_STR);
        }
        std::vector<char> mutableConfig(config.begin(), config.end());
        auto error{ lazy_dfi_validate_config(mutableConfig.data(), static_cast<int>(mutableConfig.size())) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }
}

PYBIND11_MODULE(pydfi, m) {
    // Attributes

    m.attr("__version__") = "1.0";
    m.attr("eicar") = DFI_EICAR;

    // Enumerations
    py::enum_<AIFileType>(m, "ai_file_type", py::arithmetic())
        .value("unknown", AIFileType::Unknown)
        .value("pe", AIFileType::Pe)
        .value("elf", AIFileType::Elf)
        .value("mach", AIFileType::Mach)
        .value("vect", AIFileType::Vect)
        .value("pdf", AIFileType::Pdf)
        .value("com", AIFileType::Com)
        .value("ole", AIFileType::Ole)
        .value("open_xml", AIFileType::OpenXml)
        .value("pkzip", AIFileType::Pkzip)
        .value("rar", AIFileType::Rar)
        .value("lzma", AIFileType::Lzma)
        .value("bzip2", AIFileType::Bzip2)
        .value("tar", AIFileType::Tar)
        .value("cabinet", AIFileType::Cabinet)
        .value("sfx", AIFileType::Sfx)
        .value("dotnet", AIFileType::Dotnet)
        .value("eicar", AIFileType::Eicar)
        .value("lnk)", AIFileType::Lnk);

    py::enum_<DFIErrorCode>(m, "error_code", py::arithmetic())
        .value("success", DFIErrorCode::Success)
        .value("dfi_not_initialized", DFIErrorCode::DfiNotInitialized)
        .value("invalid_parameter", DFIErrorCode::InvalidParameter);

    py::enum_<DFIScanResult>(m, "scan_result", py::arithmetic())
        .value("not_initialized", DFIScanResult::NotInitialized)
        .value("wrong_parameter", DFIScanResult::WrongParameter)
        .value("timeout_reached", DFIScanResult::TimeoutReached)
        .value("no_license", DFIScanResult::NoLicense)
        .value("success", DFIScanResult::Success)
        .value("unknown_error", DFIScanResult::UnknownError)
        .value("minimum_file_size_error", DFIScanResult::MinimumFileSizeError)
        .value("unknown_file_type", DFIScanResult::UnknownFileType)
        .value("unsupported_file_type", DFIScanResult::UnsupportedFileType)
        .value("data_is_missing", DFIScanResult::DataisMissing)
        .value("file_is_corrupted", DFIScanResult::FileisCorrupted)
        .value("invalid_archive", DFIScanResult::InvalidArchive)
        .value("maximum_archive_depth_error", DFIScanResult::MaximumArchiveDepthError)
        .value("file_too_short_for_vector", DFIScanResult::FileTooShortForVector)
        .value("unknown_vector_type", DFIScanResult::UnknownVectorType)
        .value("section_index_out_of_range", DFIScanResult::SectionIndexOutOfRange)
        .value("signatures_scan_failure", DFIScanResult::SignaturesScanFailure)
        .value("indicators_scan_failure", DFIScanResult::IndicatorsScanFailure)
        .value("runtime_error", DFIScanResult::RuntimeError)
        .value("length_error", DFIScanResult::LengthError)
        .value("bad_alloc_error", DFIScanResult::BadAllocError)
        .value("sfx_scan_success", DFIScanResult::SfxScanSuccess)
        .value("sfx_type_unsupported", DFIScanResult::SfxTypeUnsupported)
        .value("sfx_archive_missing)", DFIScanResult::SfxArchiveMissing);

    py::enum_<Verdict>(m, "verdict", py::arithmetic())
        .value("benign", Verdict::Benign)
        .value("suspicious", Verdict::Suspicious)
        .value("malware", Verdict::Malware);

    py::enum_<Score>(m, "Score", py::arithmetic())
        .value("unknown", Score::Unknown)
        .value("validate", Score::Validate)
        .value("mitigate", Score::Mitigate);

    // Classes
    py::class_<PyDfi::Dfi, std::shared_ptr<PyDfi::Dfi>>(m, "Dfi", R"pbdoc(
            Scan information provided to a callback function.
        )pbdoc")
        .def_property("depth", &PyDfi::Dfi::GetDepth, nullptr)
        .def_property("features", &PyDfi::Dfi::GetFeatures, nullptr)
        .def_property("file_data", &PyDfi::Dfi::GetFileData, nullptr)
        .def_property("file_type", &PyDfi::Dfi::GetFileType, nullptr)
        .def_property("indicators", &PyDfi::Dfi::GetIndicators, nullptr)
        .def_property("macro_content", &PyDfi::Dfi::GetMacroContent, nullptr)
        .def_property("path_in_archive", &PyDfi::Dfi::GetPathInArchive, nullptr)
        .def_property("score", &PyDfi::Dfi::GetScore, nullptr)
        .def_property("sha1", &PyDfi::Dfi::GetSha1, nullptr)
        .def_property("sha256", &PyDfi::Dfi::GetSha256, nullptr)
        .def_property("verdict", &PyDfi::Dfi::GetVerdict, nullptr, R"pbdoc(
            Benign, Suspicious, or Malware.
        )pbdoc")
        .def_property("is_archive", &PyDfi::Dfi::IsArchive, nullptr);

    py::class_<PyDfi::Scan, std::shared_ptr<PyDfi::Scan>>(m, "Scan", R"pbdoc(
            Manages scan data for the lifetime of the scan.
        )pbdoc")
        .def(py::init<const py::bytes&, const std::string&, PyDfi::PreCallback, PyDfi::PreCallback, PyDfi::PostCallback, PyDfi::ErrorCallback, const std::shared_ptr<PyDfi::ScanArguments>&>())
        .def_property_readonly("scan_results", &PyDfi::Scan::GetScanResults);

    py::class_<PyDfi::ScanArguments, std::shared_ptr<PyDfi::ScanArguments>>(m, "ScanArguments", R"pbdoc(
            Arguments that may be provided to a scan to change how it is performed.
        )pbdoc")
        .def(py::init<>())
        .def_property("features", nullptr, &PyDfi::ScanArguments::SetFeatures)
        .def_property("indicators", nullptr, &PyDfi::ScanArguments::SetIndicators)
        .def_property("macro_content", nullptr, &PyDfi::ScanArguments::SetMacroContent)
        .def_property("allowed_inner_file_types", nullptr, &PyDfi::ScanArguments::SetAllowedInnerFileTypes)
        .def_property("file_type", nullptr, &PyDfi::ScanArguments::SetFileType)
        .def_property("hash_limits", nullptr, &PyDfi::ScanArguments::SetHashLimits)
        .def_property("max_archive_entry_size", nullptr, &PyDfi::ScanArguments::SetMaxArchiveEntrySize)
        .def_property("max_archive_inner_files", nullptr, &PyDfi::ScanArguments::SetMaxArchiveInnerFiles)
        .def_property("max_scan_depth", nullptr, &PyDfi::ScanArguments::SetMaxScanDepth)
        .def_property("msi_scan", nullptr, &PyDfi::ScanArguments::SetMsiScan)
        .def_property("scan_archives", nullptr, &PyDfi::ScanArguments::SetScanArchives)
        .def_property("scan_everything", nullptr, &PyDfi::ScanArguments::SetScanEverything)
        .def_property("stop_scan_threshold", nullptr, &PyDfi::ScanArguments::SetStopScanThreshold);

    // Functions
    m.def("api_version", &PyDfi::GetApiVersion);
    m.def("cleanup", &PyDfi::Cleanup);
    m.def("find_file_type", &PyDfi::FindFileType,
        py::arg("data"));
    m.def("max_features_count", &PyDfi::GetMaxFeaturesCount);
    m.def("telemetry", &PyDfi::GetTelemetry);
    m.def("version", &PyDfi::GetVersion);
    m.def("init", &PyDfi::Init, R"pbdoc(
        Initialized the DFI library. This must be called before scanning a path.
    )pbdoc",
        py::arg("logger"));
    m.def("load_ai", &PyDfi::LoadAi, R"pbdoc(
        Load the DFI libary and resolve its exported APIs. This must be called before the remainder of the module may be used.
    )pbdoc",
        py::arg("path"));
    m.def("uses_scan_context", &PyDfi::UsesScanContext);
    m.def("reset_custom_yara_rules", &PyDfi::ResetCustomYaraRules);
    m.def("reset_detection_yara_rules", &PyDfi::ResetDetectionYaraRules);
    m.def("set_custom_yara_rules", &PyDfi::SetCustomYaraRules,
        py::arg("yarc"));
    m.def("set_detection_yara_rules", &PyDfi::SetDetectionYaraRules,
        py::arg("yarc"));
    m.def("validate_config", &PyDfi::ValidateConfig,
        py::arg("config"));

    // Exceptions
    py::register_local_exception<PyDfi::Exception>(m, "DfiException");
}
