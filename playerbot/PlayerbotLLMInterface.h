#include <atomic>
#include <string>
#include <vector>
#include <boost/json.hpp>
#include <deque>

class PlayerbotLLMInterface
{
public:
    PlayerbotLLMInterface() {}
    static std::string SanitizeForJson(const std::string& input);

    static std::string Generate(const std::string& prompt, int timeOutSeconds, int maxGenerations, std::vector<std::string>& debugLines);

    static std::vector<std::string> ParseResponse(const std::string& response, const std::string& startPattern, const std::string& endPattern, const std::string& deletePattern, const std::string& splitPattern, std::vector<std::string>& debugLines);

	static std::pair<std::vector<std::string>, boost::json::object> ParseResponseV2(const std::string& response, std::vector<std::string>& debugLines);

    static void LimitContext(std::string& context, int currentLength, std::string knownName = "");
private:
    std::atomic<int> generationCount = 0;
    std::deque<std::chrono::steady_clock::time_point> generationTimes;

	static void CollapseSpaces(std::string& str);
};

#define sPlayerbotLLMInterface MaNGOS::Singleton<PlayerbotLLMInterface>::Instance()

