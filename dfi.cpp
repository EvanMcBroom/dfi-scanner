#include <Windows.h>
#include <libdfi.hpp>
#include <magic_enum.hpp>

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
    decltype(dfi_get_depth)* lazy_dfi_get_depth;
    decltype(dfi_get_features)* lazy_dfi_get_features;
    decltype(dfi_get_file_data)* lazy_dfi_get_file_data;
    decltype(dfi_get_file_type)* lazy_dfi_get_file_type;
    decltype(dfi_get_indicators)* lazy_dfi_get_indicators;
    decltype(dfi_get_macro_content)* lazy_dfi_get_macro_content;
    decltype(dfi_get_max_features_count)* lazy_dfi_get_max_features_count;
    decltype(dfi_get_path_in_archive)* lazy_dfi_get_path_in_archive;
    decltype(dfi_get_score)* lazy_dfi_get_score;
    decltype(dfi_get_sha1)* lazy_dfi_get_sha1;
    decltype(dfi_get_sha256)* lazy_dfi_get_sha256;
    decltype(dfi_get_telemetry)* lazy_dfi_get_telemetry;
    decltype(dfi_get_verdict)* lazy_dfi_get_verdict;
    decltype(dfi_get_version)* lazy_dfi_get_version;
    decltype(dfi_init)* lazy_dfi_init;
    decltype(dfi_init_scan_arguments)* lazy_dfi_init_scan_arguments;
    decltype(dfi_is_archive)* lazy_dfi_is_archive;
    decltype(dfi_reset_custom_yara_rules)* lazy_dfi_reset_custom_yara_rules;
    decltype(dfi_scan)* lazy_dfi_scan;
    decltype(dfi_set_custom_yara_rules)* lazy_dfi_set_custom_yara_rules;
    decltype(dfi_set_features)* lazy_dfi_set_features;
    decltype(dfi_set_indicators)* lazy_dfi_set_indicators;
    decltype(dfi_set_macro_content)* lazy_dfi_set_macro_content;
    decltype(dfi_set_max_scan_depth)* lazy_dfi_set_max_scan_depth;
    decltype(dfi_set_scan_archives)* lazy_dfi_set_scan_archives;
    decltype(dfi_set_scan_everything)* lazy_dfi_set_scan_everything;
    decltype(dfi_set_stop_scan_threshold)* lazy_dfi_set_stop_scan_threshold;
    DfiScanner::Logger userLogger{ nullptr };
    
    void CppLogger(uint32_t level, wchar_t* message) {
        if (userLogger) {
            userLogger(level, message);
        }
    }
}

namespace DfiScanner {
    Dfi::Dfi(DFI** dfi)
        : dfi(dfi) {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
    }

    uint32_t Dfi::GetDepth() {
        uint32_t depth{ 0 };
        auto error{ lazy_dfi_get_depth(dfi, &depth) };
        if (error == DFIErrorCode::Success) {
            return depth;
        }
        throw Exception(error);
    }

    std::vector<char> Dfi::GetFeatures() {
        uint32_t featuresSize{ 0 };
        char* features{ 0 };
        auto error{ lazy_dfi_get_file_data(dfi, &featuresSize, &features) };
        return (error == DFIErrorCode::Success && featuresSize) ? std::vector(features, features + featuresSize) : std::vector<char>();
    }

    std::vector<char> Dfi::GetFileData() {
        uint32_t dataSize{ 0 };
        char* data{ 0 };
        auto error{ lazy_dfi_get_file_data(dfi, &dataSize, &data) };
        return (error == DFIErrorCode::Success && dataSize) ? std::vector(data, data + dataSize) : std::vector<char>();
    }

    AIFileType Dfi::GetFileType() {
        AIFileType type{ 0 };
        auto error{ lazy_dfi_get_file_type(dfi, &type) };
        if (error == DFIErrorCode::Success) {
            return type;
        }
        throw Exception(error);
    }

    std::string Dfi::GetIndicators() {
        uint32_t indicatorsSize{ 0 };
        char* indicators{ 0 };
        auto error{ lazy_dfi_get_indicators(dfi, &indicatorsSize, &indicators) };
        return (error == DFIErrorCode::Success && indicatorsSize) ? std::string(indicators, indicators + indicatorsSize) : std::string();
    }

    std::vector<char> Dfi::GetMacroContent() {
        uint32_t contentSize{ 0 };
        char* content{ 0 };
        auto error{ lazy_dfi_get_macro_content(dfi, &contentSize, &content) };
        return (error == DFIErrorCode::Success && contentSize) ? std::vector(content, content + contentSize) : std::vector<char>();
    }

    std::string Dfi::GetPathInArchive() {
        uint32_t pathSize{ 0 };
        char* path{ 0 };
        auto error{ lazy_dfi_get_path_in_archive(dfi, &pathSize, &path) };
        return (error == DFIErrorCode::Success && pathSize) ? std::string(path, path + pathSize) : std::string();
    }

    double Dfi::GetScore() {
        double score{ 0 };
        auto error{ lazy_dfi_get_score(dfi, &score) };
        if (error == DFIErrorCode::Success) {
            return score;
        }
        throw Exception(error);
    }

    std::vector<char> Dfi::GetSha1() {
        std::vector<char> sha1(20, '\0');
        lazy_dfi_get_sha1(dfi, sha1.data());
        return sha1;
    }

    std::vector<char> Dfi::GetSha256() {
        std::vector<char> sha256(32, '\0');
        lazy_dfi_get_sha256(dfi, sha256.data());
        return sha256;
    }

    Verdict Dfi::GetVerdict() {
        Verdict verdict{ 0 };
        auto error{ lazy_dfi_get_verdict(dfi, &verdict) };
        if (error == DFIErrorCode::Success) {
            return verdict;
        }
        throw Exception(error);
    }

    bool Dfi::IsArchive() {
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

    Exception::Exception(const std::string& message)
        : message(message) {
    }

    char* Exception::what() {
        return (!message.empty()) ? message.data() : "Unknown error.";
    }

    ScanArguments::ScanArguments() {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        auto error{ lazy_dfi_init_scan_arguments(&args) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    ScanArguments::~ScanArguments() {
        // Ignore any error that may occur because
        // deconstructors should not throw.
        // Reference: C++ Core Guidelines
        (void)lazy_dfi_delete_scan_arguments(args);
    }

    void ScanArguments::SetFeatures(const std::vector<char>& features) {
        auto maxFeaturesCount{ GetMaxFeaturesCount() };
        if (features.size() < (maxFeaturesCount * 8)) {
            throw Exception("Feature size not large enough to support the max feature count that may be used.");
        }
        userFeatures = features;
        auto error{ lazy_dfi_set_features(args, userFeatures.size(), userFeatures.data()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetIndicators(const std::string& indicators) {
        userIndicators = std::vector<char>(indicators.begin(), indicators.end());
        auto error{ lazy_dfi_set_indicators(args, userIndicators.size(), userIndicators.data()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetMacroContent(const std::vector<char>& macroContent) {
        userMacroContent = macroContent;
        auto error{ lazy_dfi_set_macro_content(args, userMacroContent.size(), userMacroContent.data()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetMaxScanDepth(uint32_t scanDepth) {
        auto error{ lazy_dfi_set_max_scan_depth(args, scanDepth) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetScanArchives(bool enable) {
        auto error{ lazy_dfi_set_scan_archives(args, enable) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetScanEverything(bool enable) {
        auto error{ lazy_dfi_set_scan_everything(args, enable) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ScanArguments::SetStopScanThreshold(uint32_t stopScanThreshold) {
        auto error{ lazy_dfi_set_stop_scan_threshold(args, stopScanThreshold) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void Cleanup() {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        userLogger = nullptr;
        auto error{ lazy_dfi_cleanup() };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    uint32_t GetMaxFeaturesCount() {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        uint32_t count{ 0 };
        // Will always succeed when given a valid pointer
        (void)lazy_dfi_get_max_features_count(&count);
        return count;
    }

    std::string GetTelemetry() {
        if (!ai) {
            throw Exception("AI not loaded.");
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
            throw Exception("AI not loaded.");
        }
        char* version;
        char* build;
        auto error{ lazy_dfi_get_version(&version, &build) };
        return ((error == DFIErrorCode::Success && version && build)) ? std::pair{ std::string(version), std::string(build) } : std::pair{ std::string(), std::string() };
    }

    bool LoadAi(const std::wstring& path) {
        if (ai = LoadLibraryW(path.data())) {
            // Pre-resolve all procedures to speed up API access
            if (LAZY_LOAD_PROC(ai, dfi_cleanup) &&
                LAZY_LOAD_PROC(ai, dfi_delete_scan_arguments) &&
                LAZY_LOAD_PROC(ai, dfi_get_depth) &&
                LAZY_LOAD_PROC(ai, dfi_get_features) &&
                LAZY_LOAD_PROC(ai, dfi_get_file_data) &&
                LAZY_LOAD_PROC(ai, dfi_get_file_type) &&
                LAZY_LOAD_PROC(ai, dfi_get_indicators) &&
                LAZY_LOAD_PROC(ai, dfi_get_macro_content) &&
                LAZY_LOAD_PROC(ai, dfi_get_max_features_count) &&
                LAZY_LOAD_PROC(ai, dfi_get_path_in_archive) &&
                LAZY_LOAD_PROC(ai, dfi_get_score) &&
                LAZY_LOAD_PROC(ai, dfi_get_sha1) &&
                LAZY_LOAD_PROC(ai, dfi_get_sha256) &&
                LAZY_LOAD_PROC(ai, dfi_get_telemetry) &&
                LAZY_LOAD_PROC(ai, dfi_get_verdict) &&
                LAZY_LOAD_PROC(ai, dfi_get_version) &&
                LAZY_LOAD_PROC(ai, dfi_init) &&
                LAZY_LOAD_PROC(ai, dfi_init_scan_arguments) &&
                LAZY_LOAD_PROC(ai, dfi_is_archive) &&
                LAZY_LOAD_PROC(ai, dfi_reset_custom_yara_rules) &&
                LAZY_LOAD_PROC(ai, dfi_scan) &&
                LAZY_LOAD_PROC(ai, dfi_set_custom_yara_rules) &&
                LAZY_LOAD_PROC(ai, dfi_set_features) &&
                LAZY_LOAD_PROC(ai, dfi_set_indicators) &&
                LAZY_LOAD_PROC(ai, dfi_set_macro_content) &&
                LAZY_LOAD_PROC(ai, dfi_set_max_scan_depth) &&
                LAZY_LOAD_PROC(ai, dfi_set_scan_archives) &&
                LAZY_LOAD_PROC(ai, dfi_set_scan_everything) &&
                LAZY_LOAD_PROC(ai, dfi_set_stop_scan_threshold)) {
                return true;
            }
            FreeLibrary(reinterpret_cast<HMODULE>(ai));
            ai = nullptr;
        }
        return false;
    }

    void Init(Logger logger) {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        if (logger) {
            userLogger = logger;
        }
        auto error{ lazy_dfi_init(CppLogger) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ResetCustomYaraRules() {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        // API is hardcoded to return DFIErrorCode::Success
        (void)lazy_dfi_reset_custom_yara_rules();
    }

    void Scan(const std::vector<char>& data, void* userData, PreCallback onPreScanError, PreCallback onPreScanCompletion, PostCallback onScanCompletion, ErrorCallback onScanError, const ScanArguments& args) {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        throw Exception("Not implemented.");
    }

    void SetCustomYaraRules(const std::vector<char>& yarc) {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        bool isArchive{ 0 };
        auto error{ lazy_dfi_set_custom_yara_rules(yarc.data(), yarc.size()) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }
}