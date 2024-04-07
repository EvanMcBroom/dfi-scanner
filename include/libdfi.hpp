// The C API for Deep File Inspection (DPI) as determined
// by auditing the SentinelStaticAI.dll library.
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// From extracted dv.proto
enum class AIFileType {
    Unknown = 0,
    Pe = 1,
    Elf = 2,
    Mach = 3,
    Vect = 4,
    Pdf = 5,
    Com = 6,
    Ole = 7,
    OpenXml = 8, // Microsoft Office (DOC, DOCX, EML, PPT, PPTX, XLS, XLSX)
    Pkzip = 9,
    Rar = 10,
    Lzma = 11,
    Bzip2 = 12,
    Tar = 13,
    Cabinet = 14,
    Sfx = 15,
    Dotnet = 16,
    Eicar = 17,
    Lnk = 18
};

// Value meanings are completely guessed
enum class DFIErrorCode : int32_t {
    Success = 0,
    DfiNotInitialized = 1,
    InvalidParameter = 2
};

// The type name is correct but its meaning is guessed
using DFICallbackResult = DFIErrorCode;

// Name of type is guessed but values and their meanings are known
enum class DFIScanResult {
    NotInitialized = -1,
    WrongParameter = -2,
    TimeoutReached = -3,
    NoLicense = -4,
    Success = 0,
    UnknownError = 1,
    MinimumFileSizeError = 2,
    UnknownFileType = 3,
    UnsupportedFileType = 4,
    DataisMissing = 5,
    FileisCorrupted = 6,
    InvalidArchive = 7,
    MaximumArchiveDepthError = 8,
    FileTooShortForVector = 102,
    UnknownVectorType = 103,
    SectionIndexOutOfRange = 202,
    SignaturesScanFailure = 204,
    IndicatorsScanFailure = 205,
    RuntimeError = 206,
    LengthError = 207,
    BadAllocError = 208,
    // SFX (Self - extracting files)
    SfxScanSuccess = 301,
    SfxTypeUnsupported = 302,
    SfxArchiveMissing = 303, // Could not determine the position of the archive to extract from the SFX file.
};

// These are the correct verdict options
enum class Verdict : uint32_t {
    Benign = 0,
    Suspicious = 1,
    Malware = 2
};

// Verdicts map to these score meanings in dv.proto
enum class Score {
    Unknown = 0,
    Validate = 1,
    Mitigate = 2
};

struct DFI {
    uint32_t size{ 0xb0 };
    char* data;
    uint32_t file_size;
    AIFileType file_type;
    double score;
    char* features;
    uint32_t features_size;
    char* indicators;
    uint32_t indicators_size;
    uint32_t unknown1;
    char sha1_hash[20];
    void* unknown2;
    Verdict verdict;
    bool scan_archives;
    uint32_t stop_scan_threshold;
    uint32_t max_scan_depth;
    uint32_t unknown3;
    void* unknown4;
    uint32_t depth;
    void* unknown5;
    wchar_t** path_in_archive;
    DFIScanResult scan_result;
    char* macro_content;
    uint32_t unknown6;
    uint32_t macro_content_size;
};

struct DFIScanArguments {
    bool scan_archives{ true };
    uint32_t stop_scan_threshold{ 3 };
    uint32_t max_scan_depth{ 2 }; // For archives
    bool scan_everything{ false };
    char* features{ nullptr };
    uint32_t features_size{ 0 };
    char* indicators{ nullptr };
    uint32_t indicators_size{ 0 };
    char* macro_content{ nullptr };
    uint32_t macro_content_size{ 0 };
};

using DFIScanInfoPre = struct DFI*;
using DFIScanInfoPost = struct DFI*;

using PreCallback = DFICallbackResult(__cdecl*)(void* user_data, const DFIScanInfoPre* info);
using PostCallback = DFICallbackResult(__cdecl*)(void* user_data, const DFIScanInfoPost* info);
using ErrorCallback = DFICallbackResult(__cdecl*)(void* user_data, DFIScanResult result);
using Logger = void(*)(uint32_t level, wchar_t* message);

[[maybe_unused]] DFIErrorCode dfi_cleanup();
[[maybe_unused]] DFIErrorCode dfi_delete_scan_arguments(DFIScanArguments* args);
[[maybe_unused]] DFIErrorCode dfi_get_depth(DFI** dfi, uint32_t* depth);
// Dfi will allocate feature buffers as needed. So doing it yourself is not needed.
// If you do want to allocate your own buffer though, it needs to be very large
// otherwise the heap will get curropted when Dfi uses it. This is likely some
// multiple of dfi_get_max_features_count. It also should be allocates using
// HeapAlloc and the default heap for the process.
[[maybe_unused]] DFIErrorCode dfi_get_features(DFI** dfi, uint32_t* features_size, char** features);
[[maybe_unused]] DFIErrorCode dfi_get_file_data(DFI** dfi, uint32_t* file_size, char** data);
[[maybe_unused]] DFIErrorCode dfi_get_file_type(DFI** dfi, AIFileType* file_type);
[[maybe_unused]] DFIErrorCode dfi_get_indicators(DFI** dfi, uint32_t* indicators_size, char** indicators); // Output buffer is string of size 512
[[maybe_unused]] DFIErrorCode dfi_get_macro_content(DFI** dfi, uint32_t* macro_content_size, char** macro_content);
[[maybe_unused]] DFIErrorCode dfi_get_max_features_count(uint32_t* max_features_count); // Feature size will by feature count * 8
[[maybe_unused]] DFIErrorCode dfi_get_path_in_archive(DFI** dfi, uint32_t* path_size, char** path);
[[maybe_unused]] DFIErrorCode dfi_get_score(DFI** dfi, double* score);
[[maybe_unused]] void dfi_get_sha1(DFI** dfi, char* sha1);
[[maybe_unused]] void dfi_get_sha256(DFI** dfi, char* sha256);
[[maybe_unused]] DFIErrorCode dfi_get_telemetry(char* buffer, uint32_t size);
[[maybe_unused]] DFIErrorCode dfi_get_verdict(DFI** dfi, Verdict* verdict);
[[maybe_unused]] DFIErrorCode dfi_get_version(char** version, char** hash);
[[maybe_unused]] DFIErrorCode dfi_init(Logger logger);
[[maybe_unused]] DFIErrorCode dfi_init_scan_arguments(DFIScanArguments** args);
[[maybe_unused]] DFIErrorCode dfi_is_archive(DFI** dfi, bool* status);
[[maybe_unused]] DFIErrorCode dfi_reset_custom_yara_rules();
// user_data: may be anything and will be supplied to the callbacks
[[maybe_unused]] DFIErrorCode dfi_scan(const char* data, uint32_t file_size, void* user_data, PreCallback onPreScanError, PreCallback onPreScanCompletion, PostCallback onScanCompletion, ErrorCallback onScanError, DFIScanArguments* args);
[[maybe_unused]] DFIErrorCode dfi_set_custom_yara_rules(const void* yarc, uint32_t yarc_size); // The meaning of the size argument was guessed
[[maybe_unused]] DFIErrorCode dfi_set_features(DFIScanArguments* args, uint32_t features_size, char* features);
[[maybe_unused]] DFIErrorCode dfi_set_indicators(DFIScanArguments* args, uint32_t indicators_size, char* indicators);
[[maybe_unused]] DFIErrorCode dfi_set_macro_content(DFIScanArguments* args, uint32_t macro_content_size, char* macro_content);
[[maybe_unused]] DFIErrorCode dfi_set_max_scan_depth(DFIScanArguments* args, uint32_t scan_depth);
[[maybe_unused]] DFIErrorCode dfi_set_scan_archives(DFIScanArguments* args, bool enable);
[[maybe_unused]] DFIErrorCode dfi_set_scan_everything(DFIScanArguments* args, bool enable);
[[maybe_unused]] DFIErrorCode dfi_set_stop_scan_threshold(DFIScanArguments* args, uint32_t stop_scan_threshold);

// A simple C++ API for DFI that is provided for convenience.
namespace DfiScanner {
    using Build = std::string;
    class Dfi;
    class Exception;
    class ScanArguments;
    using ErrorCallback = bool(__cdecl*)(void* userData, DFIErrorCode error);
    using Logger = void(*)(uint32_t level, const std::wstring& message);
    using PostCallback = bool(__cdecl*)(void* userData, const Dfi& info);
    using PreCallback = bool(__cdecl*)(void* userData, const Dfi& info);
    using Version = std::string;

    extern void* ai;

    class Dfi {
    public:
        Dfi(DFI** dfi);
        uint32_t GetDepth();
        std::vector<char> GetFeatures();
        std::vector<char> GetFileData();
        AIFileType GetFileType();
        std::string GetIndicators();
        std::vector<char> GetMacroContent();
        std::string GetPathInArchive();
        double GetScore();
        std::vector<char> GetSha1();
        std::vector<char> GetSha256();
        Verdict GetVerdict();
        bool IsArchive();

    private:
        ::DFI** dfi{ nullptr };
    };

    class Exception : public std::exception {
    public:
        Exception(DFIErrorCode code);
        Exception(const std::string& message);
        char* what();

    private:
        std::string message;
    };

    class ScanArguments {
    public:
        ScanArguments();
        ~ScanArguments();
        void SetFeatures(const std::vector<char>& features);
        void SetIndicators(const std::string& indicators);
        void SetMacroContent(const std::vector<char>& macroContent);
        void SetMaxScanDepth(uint32_t scanDepth);
        void SetScanArchives(bool enable);
        void SetScanEverything(bool enable);
        void SetStopScanThreshold(uint32_t stopScanThreshold);

    private:
        DFIScanArguments* args{ nullptr };
        // User data must be malleable
        std::vector<char> userMacroContent;
        std::vector<char> userIndicators;
        std::vector<char> userFeatures;
    };

    void Cleanup();
    uint32_t GetMaxFeaturesCount();
    std::string GetTelemetry();
    std::pair<Version, Build> GetVersion();
    void Init(Logger logger);
    bool LoadAi(const std::wstring& path);
    void ResetCustomYaraRules();
    void Scan(const std::vector<char>& data, void* userData, PreCallback onPreScanError, PreCallback onPreScanCompletion, PostCallback onScanCompletion, ErrorCallback onScanError, const ScanArguments& args);
    void SetCustomYaraRules(const std::vector<char>& yarc);
}