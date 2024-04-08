#include <libdfi.hpp>
#include <pybind11/pybind11.h>

// A simple C++ API for DFI to provide a pythonic interface for pybind11.
namespace PyDfi {
    using Build = std::string;
    class Dfi;
    class Exception;
    class Scan;
    class ScanArguments;
    using ErrorCallback = std::function<bool(const std::string& userData, DFIScanResult result)>;
    using Logger = std::function<void(uint32_t level, const std::string& message)>;
    using PostCallback = std::function<bool(const std::string& userData, const Dfi& info)>;
    using PreCallback = std::function<bool(const std::string& userData, const Dfi& info)>;
    using Version = std::string;

    class Dfi {
    public:
        Dfi(DFI** dfi);
        uint32_t GetDepth();
        pybind11::bytes GetFeatures();
        pybind11::bytes GetFileData();
        AIFileType GetFileType();
        std::string GetIndicators();
        pybind11::bytes GetMacroContent();
        std::string GetPathInArchive();
        double GetScore();
        pybind11::bytes GetSha1();
        pybind11::bytes GetSha256();
        Verdict GetVerdict();
        bool IsArchive();

    private:
        ::DFI** dfi{ nullptr };
    };

    class Exception : public std::exception {
    public:
        explicit Exception(DFIErrorCode code);
        explicit Exception(const char* message);
        const char* what() const noexcept override;

    private:
        std::string message;
    };

    class Scan {
    public:
        Scan(const pybind11::bytes& data, const std::string& userData, PreCallback onPreScanError, PreCallback onPreScanCompletion, PostCallback onScanCompletion, ErrorCallback onScanError, const std::shared_ptr<ScanArguments>& args);

    private:
        struct WrappedUserData {
            Scan* scanThis;
            std::string* userData;
        };

        std::shared_ptr<ScanArguments> args;
        // Scan data may need to be malleable
        std::vector<char> scanData;
        std::string userData;
        PreCallback userPreScanCompletion;
        PreCallback userPreScanError;
        ErrorCallback userScanError;
        PostCallback userScanCompletion;
        WrappedUserData wrappedUserData;

        // These return -1 on falure. That falure value was guessed
        // and likely should be changed to something else.
        static DFICallbackResult __cdecl ToCppPreScanCompletion(void* userData, const DFIScanInfoPre* info);
        static DFICallbackResult __cdecl ToCppPreScanError(void* userData, const DFIScanInfoPre* info);
        static DFICallbackResult __cdecl ToCppScanCompletion(void* userData, const DFIScanInfoPost* info);
        static DFICallbackResult __cdecl ToCppScanError(void* userData, DFIScanResult result);
    };

    class ScanArguments {
        friend class Scan;

    public:
        ScanArguments();
        ~ScanArguments();
        void SetFeatures(const pybind11::bytes& features);
        void SetIndicators(const std::string& indicators);
        void SetMacroContent(const pybind11::bytes& macroContent);
        void SetMaxScanDepth(uint32_t scanDepth);
        void SetScanArchives(bool enable);
        void SetScanEverything(bool enable);
        void SetStopScanThreshold(uint32_t stopScanThreshold);

    protected:
        DFIScanArguments* Ptr();

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
    bool LoadAi(const std::string& path);
    void ResetCustomYaraRules();
    void SetCustomYaraRules(const pybind11::bytes& yarc);
}