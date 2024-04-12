#define NOMINMAX
#include <Windows.h>
#include <codecvt>
#include <locale>
#include <magic_enum.hpp>
#include <pybind11/functional.h>
#include <pydfi.hpp>
#include <string>

#include <iostream>

namespace py = pybind11;

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

    py::bytes Dfi::GetFeatures() {
        uint32_t featuresSize{ 0 };
        char* features{ 0 };
        auto error{ lazy_dfi_get_features(dfi, &featuresSize, &features) };
        return (error == DFIErrorCode::Success && featuresSize) ? py::bytes(features, featuresSize) : py::bytes();
    }

    py::bytes Dfi::GetFileData() {
        uint32_t dataSize{ 0 };
        char* data{ 0 };
        auto error{ lazy_dfi_get_file_data(dfi, &dataSize, &data) };
        return (error == DFIErrorCode::Success && dataSize) ? py::bytes(data, dataSize) : py::bytes();
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
        return (error == DFIErrorCode::Success && indicatorsSize) ? py::bytes(indicators, indicatorsSize) : py::bytes();
    }

    py::bytes Dfi::GetMacroContent() {
        if (!lazy_dfi_get_macro_content) {
            throw Exception("Method not supported by this version of DFI.");
        }
        uint32_t contentSize{ 0 };
        char* content{ 0 };
        auto error{ lazy_dfi_get_macro_content(dfi, &contentSize, &content) };
        return (error == DFIErrorCode::Success && contentSize) ? py::bytes(content, contentSize) : py::bytes();
    }

    std::string Dfi::GetPathInArchive() {
        uint32_t pathSize{ 0 };
        wchar_t* path{ 0 };
        auto error{ lazy_dfi_get_path_in_archive(dfi, &pathSize, &path) };
        auto result{ (error == DFIErrorCode::Success && pathSize) ? std::wstring(path, path + pathSize) : std::wstring() };
        return utfConverter.to_bytes(result);
    }

    double Dfi::GetScore() {
        double score{ 0 };
        auto error{ lazy_dfi_get_score(dfi, &score) };
        if (error == DFIErrorCode::Success) {
            return score;
        }
        throw Exception(error);
    }

    py::bytes Dfi::GetSha1() {
        std::vector<char> sha1(20, '\0');
        lazy_dfi_get_sha1(dfi, sha1.data());
        return std::string(sha1.data(), sha1.data() + 20);
    }

    py::bytes Dfi::GetSha256() {
        std::vector<char> sha256(32, '\0');
        lazy_dfi_get_sha256(dfi, sha256.data());
        return std::string(sha256.data(), sha256.data() + 32);
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

    Exception::Exception(const char* message)
        : message(message) {
    }

    const char* Exception::what() const noexcept {
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

    void ScanArguments::SetFeatures(const py::bytes& features) {
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

    void ScanArguments::SetIndicators(const std::string& indicators) {
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
        if (!lazy_dfi_get_telemetry) {
            throw Exception("Method not supported by this version of DFI.");
        }
        std::string strMacroContent{ macroContent };
        userMacroContent = std::vector<char>(strMacroContent.begin(), strMacroContent.end());
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

    DFIScanArguments* ScanArguments::Ptr() {
        return args;
    }

    Scan::Scan(const py::bytes& data, const std::string& userData, PreCallback onPreScanError, PreCallback onPreScanCompletion, PostCallback onScanCompletion, ErrorCallback onScanError, const std::shared_ptr<ScanArguments>& args)
        : userData(userData), userPreScanCompletion(onPreScanCompletion), userPreScanError(onPreScanError), userScanCompletion(onScanCompletion), userScanError(onScanError), args(args) {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        std::string strData{ data };
        scanData = std::vector<char>(strData.begin(), strData.end());
        wrappedUserData.scanThis = this;
        wrappedUserData.userData = &this->userData;
        lazy_dfi_scan(scanData.data(), scanData.size(), &this->wrappedUserData, ToCppPreScanError, ToCppPreScanCompletion, ToCppScanCompletion, ToCppScanError, this->args->Ptr());
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
        if (!lazy_dfi_get_telemetry) {
            throw Exception("Method not supported by this version of DFI.");
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

    bool LoadAi(const std::string& path) {
        std::wstring utf16Path{ utfConverter.from_bytes(path) };
        if (ai = LoadLibraryW(utf16Path.data())) {
            // Pre-resolve all procedures to speed up API access
            if (LAZY_LOAD_PROC(ai, dfi_cleanup) &&
                LAZY_LOAD_PROC(ai, dfi_delete_scan_arguments) &&
                LAZY_LOAD_PROC(ai, dfi_get_depth) &&
                LAZY_LOAD_PROC(ai, dfi_get_features) &&
                LAZY_LOAD_PROC(ai, dfi_get_file_data) &&
                LAZY_LOAD_PROC(ai, dfi_get_file_type) &&
                LAZY_LOAD_PROC(ai, dfi_get_indicators) &&
                LAZY_LOAD_PROC(ai, dfi_get_max_features_count) &&
                LAZY_LOAD_PROC(ai, dfi_get_path_in_archive) &&
                LAZY_LOAD_PROC(ai, dfi_get_score) &&
                LAZY_LOAD_PROC(ai, dfi_get_sha1) &&
                LAZY_LOAD_PROC(ai, dfi_get_sha256) &&
                LAZY_LOAD_PROC(ai, dfi_get_verdict) &&
                LAZY_LOAD_PROC(ai, dfi_get_version) &&
                LAZY_LOAD_PROC(ai, dfi_init) &&
                LAZY_LOAD_PROC(ai, dfi_init_scan_arguments) &&
                LAZY_LOAD_PROC(ai, dfi_is_archive) &&
                LAZY_LOAD_PROC(ai, dfi_scan) &&
                LAZY_LOAD_PROC(ai, dfi_set_features) &&
                LAZY_LOAD_PROC(ai, dfi_set_indicators) &&
                LAZY_LOAD_PROC(ai, dfi_set_max_scan_depth) &&
                LAZY_LOAD_PROC(ai, dfi_set_scan_archives) &&
                LAZY_LOAD_PROC(ai, dfi_set_scan_everything) &&
                LAZY_LOAD_PROC(ai, dfi_set_stop_scan_threshold)) {
                LAZY_LOAD_PROC(ai, dfi_get_macro_content);
                LAZY_LOAD_PROC(ai, dfi_get_telemetry);
                LAZY_LOAD_PROC(ai, dfi_reset_custom_yara_rules);
                LAZY_LOAD_PROC(ai, dfi_set_custom_yara_rules);
                LAZY_LOAD_PROC(ai, dfi_set_macro_content);
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
        auto error{ lazy_dfi_init(ToCppLogger) };
        if (error != DFIErrorCode::Success) {
            throw Exception(error);
        }
    }

    void ResetCustomYaraRules() {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        if (!lazy_dfi_get_telemetry) {
            throw Exception("Method not supported by this version of DFI.");
        }
        // API is hardcoded to return DFIErrorCode::Success
        (void)lazy_dfi_reset_custom_yara_rules();
    }

    void SetCustomYaraRules(const py::bytes& yarc) {
        if (!ai) {
            throw Exception("AI not loaded.");
        }
        if (!lazy_dfi_get_telemetry) {
            throw Exception("Method not supported by this version of DFI.");
        }
        bool isArchive{ 0 };
        std::string strYarc{ yarc };
        auto error{ lazy_dfi_set_custom_yara_rules(strYarc.data(), strYarc.size()) };
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
        .def(py::init<const std::string&, const std::string&, PyDfi::PreCallback, PyDfi::PreCallback, PyDfi::PostCallback, PyDfi::ErrorCallback, const std::shared_ptr<PyDfi::ScanArguments>&>());

    py::class_<PyDfi::ScanArguments, std::shared_ptr<PyDfi::ScanArguments>>(m, "ScanArguments", R"pbdoc(
            Arguments that may be provided to a scan to change how it is performed.
        )pbdoc")
        .def(py::init<>())
        .def_property("features", nullptr, &PyDfi::ScanArguments::SetFeatures)
        .def_property("indicators", nullptr, &PyDfi::ScanArguments::SetIndicators)
        .def_property("macro_content", nullptr, &PyDfi::ScanArguments::SetMacroContent)
        .def_property("max_scan_depth", nullptr, &PyDfi::ScanArguments::SetMaxScanDepth)
        .def_property("scan_archives", nullptr, &PyDfi::ScanArguments::SetScanArchives)
        .def_property("scan_everything", nullptr, &PyDfi::ScanArguments::SetScanEverything)
        .def_property("stop_scan_threshold", nullptr, &PyDfi::ScanArguments::SetStopScanThreshold);

    // Functions
    m.def("cleanup", &PyDfi::Cleanup);
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
    m.def("reset_custom_yara_rules", &PyDfi::ResetCustomYaraRules);
    m.def("set_custom_yara_rules", &PyDfi::SetCustomYaraRules,
        py::arg("yarc"));

    // Exceptions
    py::register_local_exception<PyDfi::Exception>(m, "DfiException");
}
