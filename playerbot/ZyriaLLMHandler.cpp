#include "playerbot/playerbot.h"
#include <boost/json.hpp>
#include "playerbot/ZyriaLLMHandler.h"
#include "playerbot/ZyriaDebug.h"

void ZyriaLLMHandler::Process(PlayerbotAI* ai, const boost::json::object& zyriaData)
{
    if (zyriaData.contains("change_strategy"))
    {
        std::string strat = boost::json::value_to<std::string>(zyriaData.at("change_strategy"));
        ai->ChangeStrategy(strat, BotState::BOT_STATE_NON_COMBAT);
        ZyriaDebug("ZyriaLLMHandler: Applied strategy change: " + strat);
    }

    if (zyriaData.contains("custom_emote"))
    {
        std::string emote = boost::json::value_to<std::string>(zyriaData.at("custom_emote"));
        // TODO: Send emote packet
        ZyriaDebug("ZyriaLLMHandler: Emote requested: " + emote);
    }

    // Extend freely...
}
