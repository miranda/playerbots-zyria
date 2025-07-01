
#include "playerbot/playerbot.h"
#include "RpgSubActions.h"
#include "ChooseRpgTargetAction.h"
#include "playerbot/PlayerbotAIConfig.h"
#include "playerbot/strategy/values/PossibleRpgTargetsValue.h"
#include "playerbot/strategy/values/Formations.h"
#include "playerbot/strategy/values/SharedValueContext.h"
#include "EmoteAction.h"
#include "Entities/GossipDef.h"
#include "GuildCreateActions.h"
#include "Social/SocialMgr.h"
#include "playerbot/TravelMgr.h"
#include "SayAction.h"
#include "playerbot/PlayerbotLLMInterface.h"
#include <boost/json.hpp>

#include "playerbot/ZyriaDebug.h"

using namespace ai;

void RpgHelper::BeforeExecute()
{
    bot->SetSelectionGuid(guidP());

    setFacingTo(guidP());

    setFacing(guidP());
}

void RpgHelper::AfterExecute(bool doDelay, bool waitForGroup, std::string nextAction)
{
    if ((ai->HasRealPlayerMaster() || bot->GetGroup() || !urand(0,5)) && nextAction == "rpg") 
        nextAction = "rpg cancel"; 
    
    SET_AI_VALUE(std::string, "next rpg action", nextAction);

    if(doDelay)
        setDelay(waitForGroup);
}

void RpgHelper::setFacingTo(GuidPosition guidPosition)
{
    if (!sPlayerbotAIConfig.turnInRpg)
        return;

    //sServerFacade.SetFacingTo(bot, guidPosition.GetWorldObject());
    MotionMaster& mm = *bot->GetMotionMaster();
    bot->SetFacingTo(bot->GetAngle(guidPosition.GetWorldObject(bot->GetInstanceId())));
    bot->m_movementInfo.RemoveMovementFlag(MovementFlags(MOVEFLAG_SPLINE_ENABLED | MOVEFLAG_FORWARD));
}

void RpgHelper::setFacing(GuidPosition guidPosition)
{
    if (!sPlayerbotAIConfig.turnInRpg)
        return;

    if (!guidPosition.IsUnit())
        return;

    if (guidPosition.IsPlayer())
        return;


    Unit* unit = guidPosition.GetUnit(bot->GetInstanceId());

    if (unit->IsMoving())
        return;

    MotionMaster& mm = *unit->GetMotionMaster();
    unit->SetFacingTo(unit->GetAngle(bot));
    unit->m_movementInfo.RemoveMovementFlag(MovementFlags(MOVEFLAG_SPLINE_ENABLED | MOVEFLAG_FORWARD));
}

void RpgHelper::resetFacing(GuidPosition guidPosition)
{
    if (!sPlayerbotAIConfig.turnInRpg)
        return;

    if (!guidPosition.IsCreature())
        return;

    Creature* unit = guidPosition.GetCreature(bot->GetInstanceId());

    if (unit->IsMoving())
        return;

    CreatureData* data = guidPosition.GetCreatureData();

    if (data)
    {
        unit->SetFacingTo(data->orientation);
        sRandomPlayerbotMgr.AddFacingFix(bot->GetMapId(),bot->GetInstanceId(), guidPosition);
    }
}

void RpgHelper::setDelay(bool waitForGroup)
{
    if ((!ai->HasRealPlayerMaster() && !bot->GetGroup()) || (bot->GetGroup() && bot->GetGroup()->IsLeader(bot->GetObjectGuid()) && waitForGroup))
        ai->SetActionDuration(sPlayerbotAIConfig.rpgDelay);       
    else
        ai->SetActionDuration(sPlayerbotAIConfig.rpgDelay / 5);
}

bool RpgEmoteAction::Execute(Event& event)
{
    rpg->BeforeExecute();

    Unit* unit = rpg->guidP().GetUnit(bot->GetInstanceId());

    uint32 type;

    if (unit && unit->GetEntry() == 620)
    {
        type = TEXTEMOTE_CHICKEN;
        WorldPacket data(SMSG_TEXT_EMOTE);
        data << type;
        data << 1;
        data << rpg->guidP();
        bot->GetSession()->HandleTextEmoteOpcode(data);
    }
    else
        type = TalkAction::GetRandomEmote(rpg->guidP().GetUnit(bot->GetInstanceId()));

    WorldPacket p1;
    p1 << rpg->guid();
    bot->GetSession()->HandleGossipHelloOpcode(p1);

    bot->HandleEmoteCommand(type);

    if (type != TEXTEMOTE_CHICKEN)
        rpg->AfterExecute();
    else if(unit && !bot->GetNPCIfCanInteractWith(rpg->guidP(), UNIT_NPC_FLAG_QUESTGIVER) && AI_VALUE(TravelTarget*, "travel target")->GetEntry() == 620)
        rpg->AfterExecute(true,false, "rpg emote");

    DoDelay();

    return true;
}

bool RpgCancelAction::Execute(Event& event)
{
    rpg->OnCancel();  

    if (!urand(0,3) || AI_VALUE(GuidPosition, "rpg target").GetEntry() != AI_VALUE(TravelTarget*, "travel target")->GetEntry() || AI_VALUE(TravelTarget*, "travel target")->GetStatus() != TravelStatus::TRAVEL_STATUS_WORK) //1 out of 4 to ignore current travel target after cancel.
        AI_VALUE(std::set<ObjectGuid>&, "ignore rpg target").insert(AI_VALUE(GuidPosition, "rpg target")); 

    RESET_AI_VALUE(GuidPosition, "rpg target"); rpg->AfterExecute(false, false, ""); DoDelay(); 
    RESET_AI_VALUE2(int32, "manual int", "rpg ai chat line");
    RESET_AI_VALUE2(std::string, "manual string", "llmcontext rpg");
    
    return true;
};

bool RpgTaxiAction::Execute(Event& event)
{
    rpg->BeforeExecute();

    GuidPosition guidP = rpg->guidP();

    ai->Unmount();

    uint32 node = sObjectMgr.GetNearestTaxiNode(guidP.getX(), guidP.getY(), guidP.getZ(), guidP.getMapId(), bot->GetTeam());

    std::vector<uint32> nodes;
    for (uint32 i = 0; i < sTaxiPathStore.GetNumRows(); ++i)
    {
        TaxiPathEntry const* entry = sTaxiPathStore.LookupEntry(i);
        if (entry && entry->from == node && (bot->m_taxi.IsTaximaskNodeKnown(entry->to) || bot->isTaxiCheater()))
        {
            nodes.push_back(i);
        }
    }

    if (nodes.empty())
    {
        sLog.outError("Bot %s - No flight paths available", bot->GetName());
        return false;
    }

    uint32 path = nodes[urand(0, nodes.size() - 1)];
    uint32 money = bot->GetMoney();
    bot->SetMoney(money + 100000);

    TaxiPathEntry const* entry = sTaxiPathStore.LookupEntry(path);
    if (!entry)
        return false;

    TaxiNodesEntry const* nodeFrom = sTaxiNodesStore.LookupEntry(entry->from);
    TaxiNodesEntry const* nodeTo = sTaxiNodesStore.LookupEntry(entry->to);

    Creature* flightMaster = bot->GetNPCIfCanInteractWith(guidP, UNIT_NPC_FLAG_FLIGHTMASTER);
    if (!flightMaster)
    {
        sLog.outError("Bot %s cannot talk to flightmaster (%zu location available)", bot->GetName(), nodes.size());
        return false;
    }
#ifdef MANGOSBOT_TWO                
    bot->OnTaxiFlightEject(true);
#endif
    if (!bot->ActivateTaxiPathTo({ entry->from, entry->to }, flightMaster, 0))
    {
        sLog.outError("Bot %s cannot fly %u (%zu location available)", bot->GetName(), path, nodes.size());
        return false;
    }

#ifdef MANGOSBOT_TWO
    bot->ResolvePendingMount();
#endif

    sLog.outString("Bot #%d <%s> is flying from %s to %s (%zu location available)", bot->GetGUIDLow(), bot->GetName(), nodeFrom->name[0], nodeTo->name[0], nodes.size());
    bot->SetMoney(money);

    rpg->AfterExecute();

    DoDelay();

    return true;
}


bool RpgDiscoverAction::Execute(Event& event)
{
    rpg->BeforeExecute();

    GuidPosition guidP = rpg->guidP();

    uint32 node = sObjectMgr.GetNearestTaxiNode(guidP.getX(), guidP.getY(), guidP.getZ(), guidP.getMapId(), bot->GetTeam());

    if (!node)
        return false;

    Creature* flightMaster = bot->GetNPCIfCanInteractWith(guidP, UNIT_NPC_FLAG_FLIGHTMASTER);

    if (!flightMaster)
        return false;

    rpg->AfterExecute(true, true);

    DoDelay();

    return bot->GetSession()->SendLearnNewTaxiNode(flightMaster);    
}

bool RpgHealAction::Execute(Event& event)
{
    bool retVal = false;

    rpg->BeforeExecute();
    
    switch (bot->getClass())
    {
    case CLASS_PRIEST:
        retVal = ai->DoSpecificAction("lesser heal on party", Event(), true);
        break;
    case CLASS_DRUID:
        retVal=ai->DoSpecificAction("healing touch on party", Event(), true);
        break;
    case CLASS_PALADIN:
        retVal=ai->DoSpecificAction("holy light on party", Event(), true);
        break;
    case CLASS_SHAMAN:
        retVal=ai->DoSpecificAction("healing wave on party", Event(), true);
        break;
    }

    rpg->AfterExecute(true, false);

    DoDelay();

    return retVal;
}

bool RpgAIChatAction::isUseful()
{
    GuidPosition guidP = rpg->guidP();
    if (!guidP.IsUnit())
    {
        return false;
    }

    return true;
}

bool RpgAIChatAction::SpeakLine()
{
    if (packets.empty())
        return false;
    
    // Check if it's time to process the next message
    uint32 currentTime = WorldTimer::getMSTime();
    if (currentTime < m_nextMessageTime)
        return true; // Return true to indicate we're still "busy" with the previous message
    
    delayedPacket delPacket = packets.front();
    WorldPacket packet = delPacket.first;
    uint32 delay = delPacket.second;
    uint8 type, chatTag;
    uint32 lang, senderNameLength, messageLength;
    ObjectGuid senderGuid, targetGuid;
    std::string senderName, message;

    packet.rpos(0);
    packet >> type;
    packet >> lang;

    switch (type)
    {
    case CHAT_MSG_MONSTER_WHISPER:
    case CHAT_MSG_RAID_BOSS_WHISPER:
    case CHAT_MSG_RAID_BOSS_EMOTE:
    case CHAT_MSG_MONSTER_EMOTE:
        packet >> senderGuid; //Deviation from standards. To support emotes.
        packet >> senderNameLength;
        packet >> senderName;
        packet >> targetGuid;
        break;

    case CHAT_MSG_SAY:
    case CHAT_MSG_PARTY:
    case CHAT_MSG_YELL:
        packet >> senderGuid;
        packet >> senderGuid;
        break;

    case CHAT_MSG_MONSTER_SAY:
    case CHAT_MSG_MONSTER_YELL:
        packet >> senderGuid;
        packet >> senderNameLength;
        packet >> senderName;
        packet >> targetGuid;
        break;
    default:
        packet >> senderGuid;
        break;
    }

    packet >> messageLength;
    packet >> message;

    packet >> chatTag;

    if (bot->GetObjectGuid() == senderGuid)
    {
        if (type == CHAT_MSG_EMOTE)
            bot->TextEmote(message.c_str());
        else
            bot->Say(message.c_str(), lang);
        message = bot->GetName() + std::string(": ") + message;
    }
    else
    {
        Unit* unit = ai->GetUnit(senderGuid);

        if (unit)
        {
            if (type == CHAT_MSG_MONSTER_EMOTE)
            {
                std::string emote = unit->GetName() + std::string(" ") + message;
                unit->MonsterTextEmote(emote.c_str(), bot);
            }
            else
            {
                unit->MonsterSay(message.c_str(), lang, bot);               
            }
            
            message = unit->GetName() + std::string(": ") + message;
        }
    }

    if (message.find("d:") == std::string::npos)
    {
        std::string llmContext = AI_VALUE(std::string, "manual string::llmcontext rpg");
        llmContext = llmContext + " " + message;
        PlayerbotLLMInterface::LimitContext(llmContext, llmContext.size());
        SET_AI_VALUE(std::string, "manual string::llmcontext rpg", llmContext);
    }

    // After processing the message, update the next message time
    m_nextMessageTime = currentTime + delay;

    packets.pop();

    this->SetDuration(uint32(delay/1000.0f));

    return true;
}

bool RpgAIChatAction::WaitForLines()
{
    if (!futPackets.valid())
        return false;

    if (futPackets.wait_for(std::chrono::seconds(0)) == std::future_status::timeout)
        return true;

    for (auto delayedReply : futPackets.get())
        packets.push(delayedReply);

    return false;
}

bool RpgAIChatAction::RequestNewZyriaLines()
{
    if (packets.size())
        return false;

    if (futPackets.valid())
        return false;

    GuidPosition guidP = rpg->guidP();
    Unit* unit = guidP.GetUnit(bot->GetInstanceId());
	if (unit->IsPlayer())
	{
		ZyriaDebug("Blocking RPG AI chat attempt with non-NPC", "RPG DEBUG");
		return false;
	}

    PlayerbotAI* botAi = bot ? bot->GetPlayerbotAI() : nullptr;

	if (!botAi)
		return false;

	time_t cooldown = botAi->GetRPGChatCooldown();
	std::string botName = bot->GetName();

	if (cooldown > time(nullptr))
	{
		ZyriaDebug(botName + " is on RPG chat cooldown", "DEBUG RPG");
		return false;
	}

    int32 chatLine = AI_VALUE2(int32, "manual int", "rpg ai chat line");

    if (chatLine == -1)
        return false;

    if (chatLine == 0) {
        chatLine = urand(3, 6);
	}

	if (chatLine < 0 || chatLine > 1000)	// Prevents corrupted chatLine numbers that never end
		chatLine = 2;						// Reset to 2 to give bot a chance to speak more

	std::string unitName = unit->GetName();
	boost::json::object triggers;
	
	triggers["start_quest"]	= AI_VALUE2(bool, "trigger active", "rpg start quest");
	triggers["end_quest"]	= AI_VALUE2(bool, "trigger active", "rpg end quest");
	triggers["repair"]		= AI_VALUE2(bool, "trigger active", "rpg repair");
	triggers["sell"]		= AI_VALUE2(bool, "trigger active", "rpg sell");
	triggers["buy"]			= AI_VALUE2(bool, "trigger active", "rpg buy");

	std::string chatTopic;

    switch (urand(0, 10))
    {
    case 0:
        // Bot wants to ask NPC about the zone
		chatTopic = "zone";
        break;
    case 1:
        // Bot wants to ask NPC about lore they know about
		chatTopic = "lore";
        break;
    case 2:
        // Bot wants to ask NPC about recent events
		chatTopic = "events";
        break;
    case 3:
        // Bot wants to ask NPC about nearby NPCs
		chatTopic = "npcs";
        break;
    default:
        // Bot wants to ask have a chat with NPC
		chatTopic = "general";
        break;
    }
	if (chatLine == 1)
        // Tell LLM to have bot say goodbye to NPC
		chatTopic = "goodbye";

	boost::json::object botDetails, unitDetails, unitOptions, jsonData;
	std::pair<std::string, std::string> botZoneData = WorldPosition(bot).getZoneAndSubzoneNames();

	// Get current time in milliseconds since epoch
	auto now = std::chrono::system_clock::now();
	auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();

	// Populate bot details
	botDetails["type"]		= "bot";
	botDetails["name"]		= botName;
	botDetails["gender"]	= bot->getGender() == GENDER_MALE ? "male" : "female";
	botDetails["level"]		= std::to_string(bot->GetLevel());
	botDetails["race"]		= ChatHelper::formatRace(bot->getRace());
	botDetails["class"]		= ChatHelper::formatClass(bot->getClass());
	botDetails["spec"]		= ChatHelper::specName(bot);
	botDetails["guild"]		= ChatHelper::getGuildName(bot);
	botDetails["continent"] = WorldPosition(bot).getContinentName();
	botDetails["zone"]		= botZoneData.first; 
	botDetails["subzone"]	= botZoneData.second;

	FactionTemplateEntry const* factionTemplate = unit->GetFactionTemplateEntry();
	uint32 factionId = factionTemplate ? factionTemplate->faction : 0;

	// Populate unit details
	unitDetails["type"]		= "npc";
	unitDetails["name"]		= unitName;
	unitDetails["gender"]	= unit->getGender() == GENDER_MALE ? "male" : "female";
	unitDetails["level"]	= std::to_string(unit->GetLevel());
	unitDetails["class"]	= ChatHelper::formatClass(unit->getClass());
	unitDetails["faction"]	= ChatHelper::formatFactionName(factionId);

	if (unit->IsCreature())
	{
		Creature* creature = static_cast<Creature*>(unit);
		switch (creature->GetCreatureType())
		{
		case CREATURE_TYPE_BEAST:
			unitDetails["creature_type"] = "beast";
			break;
		case  CREATURE_TYPE_DRAGONKIN:
			unitDetails["creature_type"] = "dragonkin";
			break;
		case      CREATURE_TYPE_DEMON:
			unitDetails["creature_type"] = "demon";
			break;
		case    CREATURE_TYPE_ELEMENTAL:
			unitDetails["creature_type"] = "elemental";
			break;
		case    CREATURE_TYPE_GIANT:
			unitDetails["creature_type"] = "giant";
			break;
		case   CREATURE_TYPE_UNDEAD:
			unitDetails["creature_type"] = "undead";
			break;
		case  CREATURE_TYPE_HUMANOID:
			unitDetails["creature_type"] = "humanoid";
			break;
		case  CREATURE_TYPE_CRITTER:
			unitDetails["creature_type"] = "critter";
			break;
		case  CREATURE_TYPE_MECHANICAL:
			unitDetails["creature_type"] = "mechanical";
			break;
		case  CREATURE_TYPE_NOT_SPECIFIED:
			unitDetails["creature_type"] = "being";
			break;
		case  CREATURE_TYPE_TOTEM:
			unitDetails["creature_type"] = "totem";
			break;
		default:
			unitDetails["creature_type"] = "unknown";
		}
		unitDetails["creature_subname"] = creature->GetSubName() ? std::string(creature->GetSubName()) : "";

		CreatureInfo const* cInfo = ObjectMgr::GetCreatureTemplate(creature->GetEntry());
		unitOptions["npc_flags"] = cInfo ? cInfo->NpcFlags : 0;

		bool canUnlearnTalents = false;
		bool canUnlearnPetSkills = false;

		if (cInfo && (cInfo->NpcFlags & UNIT_NPC_FLAG_TRAINER)) // Only check if it's a trainer!
		{
			GossipMenuItemsMapBounds menuBounds = sObjectMgr.GetGossipMenuItemsMapBounds(creature->GetDefaultGossipMenuId());
			for (auto& gossip = menuBounds.first; gossip != menuBounds.second; ++gossip) {
				if (gossip->second.option_id == GOSSIP_OPTION_UNLEARNTALENTS) {
					canUnlearnTalents = true;
				}
				if (gossip->second.option_id == GOSSIP_OPTION_UNLEARNPETSKILLS) {
					canUnlearnPetSkills = true;
				}
			}
		}
		unitOptions["talents"] = canUnlearnTalents;
		unitOptions["pet_skills"] = canUnlearnPetSkills;
		unitDetails["npc_options"] = unitOptions;
	}

	// Populate JSON data
	jsonData["message_type"]	= "rpg";
	jsonData["bot"]				= botDetails;
	jsonData["npc"]				= unitDetails;
	jsonData["expansion"]		= sPlayerbotAIConfig.zyriaExpansionSelect;
	jsonData["llm_channel"]		= "RPG_" + botName + "_" + unitName;
	jsonData["rpg_triggers"]	= triggers;
	jsonData["chat_topic"]		= chatTopic;
	jsonData["time_created"]	= timestamp;

	// Clone JSON data for bot and NPC
	boost::json::object botJsonData = jsonData;
	boost::json::object npcJsonData = jsonData;

	botJsonData["speaker_role"] = "bot";
	npcJsonData["speaker_role"] = "npc";

	std::string botJson = boost::json::serialize(botJsonData);
	std::string npcJson = boost::json::serialize(npcJsonData);

	ZyriaDebug("RPG AI chat action between bot <" + botName + "> and unit <" + unitName + "> - chatLine = " + std::to_string(chatLine), "DEBUG RPG");
	ZyriaDebug("Serialized RPG request JSON for bot <" + botName + ">: " + botJson, "DEBUG RPG");
	ZyriaDebug("Serialized RPG request JSON for unit <" + unitName + ">: " + npcJson, "DEBUG RPG");

    WorldSession* session = bot->GetSession();
    
	bool debug = bot->GetPlayerbotAI()->HasStrategy("debug llm", BotState::BOT_STATE_NON_COMBAT);
    
	uint32 lang = bot->GetTeam() == ALLIANCE ? LANG_COMMON : LANG_ORCISH;

	WorldPacket botChatTemplate, botEmoteTemplate, npcChatTemplate, npcEmoteTemplate, systemTemplate = ChatReplyAction::GetPacketTemplate(SMSG_CHAT_RESTRICTED, CHAT_MSG_MONSTER_WHISPER, bot, GetMaster());

	botChatTemplate = ChatReplyAction::GetPacketTemplate(CMSG_MESSAGECHAT, CHAT_MSG_SAY, bot, nullptr);
	botEmoteTemplate = ChatReplyAction::GetPacketTemplate(CMSG_MESSAGECHAT, CHAT_MSG_EMOTE, bot, nullptr);
	npcChatTemplate = ChatReplyAction::GetPacketTemplate(SMSG_CHAT_RESTRICTED, CHAT_MSG_MONSTER_SAY, unit, bot);
	npcEmoteTemplate = ChatReplyAction::GetPacketTemplate(SMSG_CHAT_RESTRICTED, CHAT_MSG_MONSTER_EMOTE, unit, bot);
	
	futurePackets botFuture = std::async(std::launch::async, ChatReplyAction::GenerateResponsePackets,
		botJson, botChatTemplate, botEmoteTemplate, systemTemplate, "", "", "", "", debug, bot->GetObjectGuid());

	ai->SendDelayedPacket(session, std::move(botFuture));  // Send bot lines normally

	// Then assign futPackets for the NPC
	futPackets = std::async(std::launch::async, ChatReplyAction::GenerateResponsePackets,
		npcJson, npcChatTemplate, npcEmoteTemplate, systemTemplate, "", "", "", "", debug, 0);

    if (!urand(0, 10))
	{
		int32 delta = urand(-2, 2);
		chatLine = std::clamp(chatLine + delta, 0, 7);	
	}
    chatLine--;

    if (chatLine == 0)
        chatLine = -1;
    else
    {
        SET_AI_VALUE(std::string, "next rpg action", "rpg ai chat");
    }

    SET_AI_VALUE2(int32, "manual int", "rpg ai chat line", chatLine);
	
	// Update RPG chat cooldown
	botAi->UpdateRPGChatCooldown();
	ZyriaDebug("Successfully generated RPG chat requests for bot <" + botName + "> and unit <" + unitName + ">", "DEBUG RPG");

    return true;
}

bool RpgAIChatAction::RequestNewLines()
{
    if (packets.size())
        return false;

    if (futPackets.valid())
        return false;

    int32 chatLine = AI_VALUE2(int32, "manual int", "rpg ai chat line");

    if (chatLine == -1)
        return false;

    if (chatLine == 0)
        chatLine = urand(5, 11);

    bool botIstalking = (chatLine % 2 == 0);

	if (chatLine < 0 || chatLine > 1000)  // Prevents corrupted chatLine numbers that never end
		chatLine = botIstalking ? 2 : 3;  // Reset to an even or odd value accordingly

    GuidPosition guidP = rpg->guidP();

    std::string llmContext = AI_VALUE2(std::string, "manual string", "llmcontext rpg");

    Unit* unit = guidP.GetUnit(bot->GetInstanceId());

    std::map<std::string, std::string> placeholders;
    if(botIstalking)
        ChatReplyAction::GetAIChatPlaceholders(placeholders, bot, unit);
    else
        ChatReplyAction::GetAIChatPlaceholders(placeholders, unit, bot);
    ChatReplyAction::GetAIChatPlaceholders(placeholders, bot, "bot");
    ChatReplyAction::GetAIChatPlaceholders(placeholders, unit, "unit", bot);

    std::string prePrompt = sPlayerbotAIConfig.llmPreRpgPrompt;

    if (AI_VALUE2(bool, "trigger active", "rpg start quest"))
        prePrompt += " <unit name> can offer <bot name> a new quest.";
    else if (AI_VALUE2(bool, "trigger active", "rpg end quest"))
        prePrompt += " <bot name> has just finished a quest for <unit name>.";

    if (AI_VALUE2(bool, "trigger active", "rpg repair"))
        prePrompt += " <unit name> can repair <bot name>'s broken equipment.";
    else if (AI_VALUE2(bool, "trigger active", "rpg sell"))
        prePrompt += " <bot name> has items <unit name> will buy.";
    else if (AI_VALUE2(bool, "trigger active", "rpg buy"))
        prePrompt += " <unit name> has items <bot name> wants to buy.";

    if (!placeholders["<unit gossip>"].empty())
        prePrompt += " <unit name>: <unit gossip>";

    switch (urand(0, 10))
    {
    case 0:
        prePrompt += " <bot name> wants to ask <unit name> about the zone.";
        break;
    case 1:
        prePrompt += " <bot name> wants to ask <unit name> about lore they know about.";
        break;
    case 2:
        prePrompt += " <bot name> wants to ask <unit name> about recent events.";
        break;
    case 3:
        prePrompt += " <bot name> wants to ask <unit name> about nearby npcs.";
        break;
    default:
        prePrompt += " <bot name> wants to ask have a chat with <unit name>.";
        break;
    }

    std::string postPompt;

    if (chatLine == 2)
        postPompt = "[<bot name> has to go. Say goodbye.]";

    postPompt += sPlayerbotAIConfig.llmPostPrompt;

    std::map<std::string, std::string> jsonFill;
    jsonFill["<pre prompt>"] = prePrompt;
    jsonFill["<prompt>"] = "";
    jsonFill["<post prompt>"] = postPompt;

    for (auto& prompt : jsonFill)
    {
        prompt.second = BOT_TEXT2(prompt.second, placeholders);
    }

    uint32 currentLength = jsonFill["<pre prompt>"].size() + jsonFill["<context>"].size() + jsonFill["<prompt>"].size() + llmContext.size();
    PlayerbotLLMInterface::LimitContext(llmContext, currentLength);
    jsonFill["<context>"] = llmContext;

    for (auto& prompt : jsonFill)
    {
        prompt.second = PlayerbotLLMInterface::SanitizeForJson(prompt.second);
    }

    for (auto& prompt : placeholders) //Sanitize now instead of earlier to prevent double Sanitation
    {
        prompt.second = PlayerbotLLMInterface::SanitizeForJson(prompt.second);
    }

    std::string startPattern, endPattern, deletePattern, splitPattern;
    startPattern = PlayerbotTextMgr::GetReplacePlaceholders(sPlayerbotAIConfig.llmResponseStartPattern, placeholders);
    endPattern = PlayerbotTextMgr::GetReplacePlaceholders(sPlayerbotAIConfig.llmResponseEndPattern, placeholders);
    deletePattern = PlayerbotTextMgr::GetReplacePlaceholders(sPlayerbotAIConfig.llmResponseDeletePattern, placeholders);
    splitPattern = PlayerbotTextMgr::GetReplacePlaceholders(sPlayerbotAIConfig.llmResponseSplitPattern, placeholders);

    std::string json = PlayerbotTextMgr::GetReplacePlaceholders(sPlayerbotAIConfig.llmApiJson, jsonFill);

    json = PlayerbotTextMgr::GetReplacePlaceholders(json, placeholders);

    WorldSession* session = bot->GetSession();

    bool debug = bot->GetPlayerbotAI()->HasStrategy("debug llm", BotState::BOT_STATE_NON_COMBAT);

    uint32 lang = bot->GetTeam() == ALLIANCE ? LANG_COMMON : LANG_ORCISH;

    WorldPacket chatTemplate, emoteTemplate, systemTemplate = ChatReplyAction::GetPacketTemplate(SMSG_CHAT_RESTRICTED, CHAT_MSG_MONSTER_WHISPER, bot, GetMaster());
    if (botIstalking)
    {
        chatTemplate = ChatReplyAction::GetPacketTemplate(SMSG_CHAT_RESTRICTED, CHAT_MSG_SAY, bot, nullptr);
        emoteTemplate = ChatReplyAction::GetPacketTemplate(SMSG_CHAT_RESTRICTED, CHAT_MSG_EMOTE, bot, nullptr);
    }
    else
    {
        chatTemplate = ChatReplyAction::GetPacketTemplate(SMSG_CHAT_RESTRICTED, CHAT_MSG_MONSTER_SAY, unit, bot);
        emoteTemplate = ChatReplyAction::GetPacketTemplate(SMSG_CHAT_RESTRICTED, CHAT_MSG_MONSTER_EMOTE, unit, bot);
    }

	futPackets = std::async(std::launch::async, [=]() -> delayedPackets {
		return ChatReplyAction::GenerateResponsePackets(json, chatTemplate, emoteTemplate, systemTemplate,	startPattern, endPattern, deletePattern, splitPattern, debug);
	});

    if (!urand(0, 10))
	{
		int32 delta = urand(-2, 2) * 2;  // -4, -2, 0, 2, or 4
		chatLine = std::clamp(chatLine + delta, 0, 12);	
	}
    chatLine--;

    if (chatLine == 0)
        chatLine = -1;
    else
    {
        SET_AI_VALUE(std::string, "next rpg action", "rpg ai chat");
    }

    SET_AI_VALUE2(int32, "manual int", "rpg ai chat line", chatLine);

    return true;
}

bool RpgAIChatAction::Execute(Event& event)
{
    if (WaitForLines())
        return true;

    if (SpeakLine())
        return true;

	if (sPlayerbotAIConfig.llmUseZyriaServer)
	{
		if (RequestNewZyriaLines())
			return true;
	}
	else
	{
		if (RequestNewLines())
			return true;
	}

    return false;
}

void RpgAIChatAction::ManualChat(GuidPosition target, const std::string& line)
{  
	if (sPlayerbotAIConfig.llmUseZyriaServer)
	{
		ai->TellDebug(ai->GetMaster(), "Manual chat not currently supported by Zyria LLM server", "debug rpg");
		return;
	}

	SET_AI_VALUE(GuidPosition, "rpg target", target);

    std::string llmContext = GAI_VALUE2(std::string, "global string", "llmcontext manual" + std::to_string(target.GetCounter()));

    if (line == "clear")
    {
        llmContext.clear();
        SET_GAI_VALUE2(std::string, "global string", "llmcontext manual" + std::to_string(target.GetCounter()), llmContext);
        bot->SendMessageToPlayer("<conversation restarted>");
        return;
    }
    else if (line == "undo")
    {
        Unit* unit = target.GetUnit(bot->GetInstanceId());
        uint32 lastBot = llmContext.rfind(bot->GetName() + std::string(":"));
        uint32 lastUnit = llmContext.rfind(unit->GetName() + std::string(":"));

        llmContext = llmContext.substr(0, std::max(lastBot,lastUnit));
        SET_GAI_VALUE2(std::string, "global string", "llmcontext manual" + std::to_string(target.GetCounter()), llmContext);
        bot->SendMessageToPlayer("<last message remove>");
        return;
    }
    else if (line == "impersonate")
    {
        SET_AI_VALUE2(int32, "manual int", "rpg ai chat line", 10);

        Unit* unit = target.GetUnit(bot->GetInstanceId());

        std::string unitLine = line.substr(12);

        if (line.find("*") == 0)
            unit->MonsterTextEmote(unitLine.c_str(), bot);
        else
            unit->MonsterSay(unitLine.c_str(), LANG_UNIVERSAL, bot);

        llmContext += std::string(" ") + bot->GetName() + std::string(":") + line;
        SET_GAI_VALUE2(std::string, "global string", "llmcontext manual" + std::to_string(target.GetCounter()), llmContext);
        return;
    }
    else if (line == "continue")
    {
        Unit* unit = target.GetUnit(bot->GetInstanceId());
        uint32 lastBot = llmContext.rfind(bot->GetName() + std::string(":"));
        uint32 lastUnit = llmContext.rfind(unit->GetName() + std::string(":"));

        if(lastBot < lastUnit)
            SET_AI_VALUE2(int32, "manual int", "rpg ai chat line", 11);
        else
            SET_AI_VALUE2(int32, "manual int", "rpg ai chat line", 12);
    }
    else
    {
        SET_AI_VALUE2(int32, "manual int", "rpg ai chat line", 11);

        if (line.find("*") == 0)
            bot->TextEmote(line);
        else
            bot->Say(line, LANG_UNIVERSAL);

        llmContext += std::string(" ") + bot->GetName() + std::string(":") + line;
    }

    SET_AI_VALUE(std::string, "manual string::llmcontext rpg", llmContext);
        

    RequestNewLines();

    futPackets.wait();

    WaitForLines();

    while (packets.size())
    {
        uint32 delay = packets.front().second;
        SpeakLine();

        if(packets.size())
            std::this_thread::sleep_for(std::chrono::milliseconds(delay));
    }

    llmContext = AI_VALUE(std::string, "manual string::llmcontext rpg");
    SET_GAI_VALUE2(std::string, "global string", "llmcontext manual" + std::to_string(target.GetCounter()), llmContext);
}

bool RpgTradeUsefulAction::IsTradingItem(uint32 entry)
{
    TradeData* trade = bot->GetTradeData();

    if (!trade)
        return false;

    for (uint8 i = 0; i < TRADE_SLOT_TRADED_COUNT; i++)
    {
        Item* tradeItem = trade->GetItem(TradeSlots(i));

        if (tradeItem && tradeItem->GetEntry() == entry)
            return true;;
    }

    return false;
}

bool RpgTradeUsefulAction::Execute(Event& event)
{
    rpg->BeforeExecute();

    GuidPosition guidP = AI_VALUE(GuidPosition, "rpg target");

    Player* player = guidP.GetPlayer();

    if (!player)
        return false;

    std::list<Item*> items = AI_VALUE(std::list<Item*>, "items useful to give");

    if (items.empty())
        return false;

    Item* item = items.front();

    std::ostringstream param;

    param << chat->formatWorldobject(player);
    param << " ";
    param << chat->formatItem(item);

    if (ai->IsRealPlayer() && !bot->GetTradeData()) //Start the trade from the other side to open the window
    {
        WorldPacket packet(CMSG_INITIATE_TRADE);
        packet << bot->GetObjectGuid();
        player->GetSession()->HandleInitiateTradeOpcode(packet);
    }

    if (!IsTradingItem(item->GetEntry()))
        ai->DoSpecificAction("trade", Event("rpg action", param.str().c_str()), true);

    bool isTrading = bot->GetTradeData();

    if (isTrading)
    {
        if (IsTradingItem(item->GetEntry())) //Did we manage to add the item to the trade?
        {
            if (bot->GetGroup() && bot->GetGroup()->IsMember(guidP))
                ai->TellPlayerNoFacing(GetMaster(), "You can use this " + chat->formatItem(item) + " better than me, " + player->GetName() + ".", PlayerbotSecurityLevel::PLAYERBOT_SECURITY_ALLOW_ALL, false);
            else
                bot->Say("You can use this " + chat->formatItem(item) + " better than me, " + player->GetName() + ".", (bot->GetTeam() == ALLIANCE ? LANG_COMMON : LANG_ORCISH));

            if (!urand(0, 4) || items.size() < 2) //Complete the trade if we have no more items to trade.
            {
                //bot->Say("End trade with" + chat->formatWorldobject(player), (bot->GetTeam() == ALLIANCE ? LANG_COMMON : LANG_ORCISH));
                WorldPacket p;
                uint32 status = TRADE_STATUS_TRADE_ACCEPT;
                p << status;
                bot->GetSession()->HandleAcceptTradeOpcode(p);
            }
        }
        //else
        //   bot->Say("Start trade with" + chat->formatWorldobject(player), (bot->GetTeam() == ALLIANCE ? LANG_COMMON : LANG_ORCISH));

        ai->SetActionDuration(sPlayerbotAIConfig.rpgDelay);
    }

    rpg->AfterExecute(isTrading, true, isTrading ? "rpg trade useful" : "rpg");

    DoDelay();

    return isTrading;
}

bool RpgEnchantAction::Execute(Event& event)
{
    rpg->BeforeExecute();

    GuidPosition guidP = AI_VALUE(GuidPosition, "rpg target");

    Player* player = guidP.GetPlayer();

    if (!player)
        return false;

    std::list<Item*> items = AI_VALUE(std::list<Item*>, "items useful to enchant");

    if (items.empty())
        return false;

    std::vector<uint32> enchantSpells = AI_VALUE(std::vector<uint32>, "enchant spells");

    //Needs more logic to pick best enchant to apply instead of a random one that's bette than current.
    std::shuffle(enchantSpells.begin(), enchantSpells.end(), *GetRandomGenerator());

    for (auto& spellId : enchantSpells)
    {
        Item* item = PAI_VALUE2(Item*, "item for spell", spellId);

        if (std::find(items.begin(), items.end(), item) == items.end())
            continue;

        std::ostringstream param;

        param << chat->formatWorldobject(bot);
        param << " ";
        param << chat->formatItem(item);

        ai->TellDebug(ai->GetMaster(), "enchanting" + param.str(), "debug rpg");

        if (player->isRealPlayer() && !player->GetTradeData()) //Start the trade from the other side to open the window
        {
            ai->TellDebug(ai->GetMaster(), "open trade window", "debug rpg");
            WorldPacket packet(CMSG_INITIATE_TRADE);
            packet << player->GetObjectGuid();
            bot->GetSession()->HandleInitiateTradeOpcode(packet);
        }

        if (!player->GetTradeData() || !player->GetTradeData()->HasItem(item->GetObjectGuid()))
        {
            ai->TellDebug(ai->GetMaster(), "starting trade", "debug rpg");
            player->GetPlayerbotAI()->DoSpecificAction("trade", Event("rpg action", param.str().c_str()), true);
        }

        bool isTrading = bot->GetTradeData();

        if (isTrading)
        {
            if (player->GetTradeData()->HasItem(item->GetObjectGuid())) //Did we manage to add the item to the trade?
            {
                uint32 duration;
                Unit* target = nullptr;

                ai->TellDebug(ai->GetMaster(), "set enchant spell", "debug rpg");
                bool didCast = ai->CastSpell(spellId, target, item, true, &duration);

                if (didCast)
                {
                    ai->TellDebug(ai->GetMaster(), "accept trade", "debug rpg");
                    if (bot->GetGroup() && bot->GetGroup()->IsMember(guidP))
                        ai->TellPlayerNoFacing(GetMaster(), "Let me enchant this " + chat->formatItem(item) + " with " + chat->formatSpell(spellId) + " for you " + player->GetName() + ".", PlayerbotSecurityLevel::PLAYERBOT_SECURITY_ALLOW_ALL, false);
                    else
                        bot->Say("Let me enchant this " + chat->formatItem(item) + " with " + chat->formatSpell(spellId) + " for you " + player->GetName() + ".", (bot->GetTeam() == ALLIANCE ? LANG_COMMON : LANG_ORCISH));

                    WorldPacket p;
                    uint32 status = TRADE_STATUS_TRADE_ACCEPT;
                    p << status;
                    bot->GetSession()->HandleAcceptTradeOpcode(p);
                }
            }

            ai->SetActionDuration(sPlayerbotAIConfig.rpgDelay);            
        }

        rpg->AfterExecute(isTrading, true, isTrading ? "rpg enchant" : "rpg");

        DoDelay();

        return isTrading;
    }

    return false;
}

bool RpgDuelAction::isUseful()
{
    // do not offer duel in non pvp areas
    if (sPlayerbotAIConfig.IsInPvpProhibitedZone(sServerFacade.GetAreaId(bot)))
        return false;

    // Players can only fight a duel with each other outside (=not inside dungeons and not in capital cities)
    AreaTableEntry const* casterAreaEntry = GetAreaEntryByAreaID(sServerFacade.GetAreaId(bot));
    if (casterAreaEntry && !(casterAreaEntry->flags & AREA_FLAG_DUEL))
    {
        // Dueling isn't allowed here
        return false;
    }

    return true;
}

bool RpgDuelAction::Execute(Event& event)
{
    GuidPosition guidP = AI_VALUE(GuidPosition, "rpg target");

    Player* player = guidP.GetPlayer();

    if (!player)
        return false;   

    return ai->DoSpecificAction("cast", Event("rpg action", chat->formatWorldobject(player) + " 7266"), true);
}

bool RpgItemAction::Execute(Event& event)
{
    Player* requester = event.getOwner() ? event.getOwner() : GetMaster();
    GuidPosition guidP = AI_VALUE(GuidPosition, "rpg target"), objectGuidP;

    if (sServerFacade.isMoving(bot))
    {
        ai->StopMoving();
        rpg->AfterExecute(true, false, "rpg item");
        return true;
    }

    GameObject* gameObjectTarget = nullptr;
    Unit* unitTarget = nullptr;
    if (guidP.IsUnit())
    {
        unitTarget = guidP.GetUnit(bot->GetInstanceId());
    }
    else if (guidP.IsGameObject())
    {
        gameObjectTarget = guidP.GetGameObject(bot->GetInstanceId());
    }

    std::list<Item*> questItems = AI_VALUE2(std::list<Item*>, "inventory items", "quest");

    bool used = false;
    for (Item* item : questItems)
    {
        if (AI_VALUE2(bool, "can use item on", Qualified::MultiQualify({ std::to_string(item->GetProto()->ItemId),guidP.to_string() }, ",")))
        {
            if (gameObjectTarget)
            {
                used = UseItem(requester, item->GetEntry(), gameObjectTarget);
            }
            else
            {
                used = UseItem(requester, item->GetEntry(), unitTarget);
            }
        }
    }

    if (used && !GetDuration())
    {
        SetDuration(sPlayerbotAIConfig.globalCoolDown);
    }

    return used;
}
bool RpgSpellClickAction::Execute(Event& event)
{
    rpg->BeforeExecute();

    GuidPosition guidP = rpg->guidP();

#ifdef MANGOSBOT_TWO
    if (!guidP.IsCreatureOrVehicle())
#endif
        return false;
   
    bool result = ai->HandleSpellClick(guidP);
    
    rpg->AfterExecute(result);
    DoDelay();
    
    return result;
}
