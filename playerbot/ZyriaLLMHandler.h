// ZyriaLLMHandler.h
#pragma once

#include "PlayerbotAI.h"
#include <boost/json/object.hpp>

class ZyriaLLMHandler
{
public:
    // Entry point
    static void Process(PlayerbotAI* ai, const boost::json::object& zyriaData);

private:
    static void HandleChangeStrategy(PlayerbotAI* ai, const boost::json::object& zyriaData);
    static void HandleEmote(PlayerbotAI* ai, const boost::json::object& zyriaData);
    static void HandleCustom(PlayerbotAI* ai, const boost::json::object& zyriaData);
};
