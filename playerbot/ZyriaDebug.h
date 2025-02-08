#ifndef ZYRIA_DEBUG_H
#define ZYRIA_DEBUG_H

#include <fstream>
#include <string>
#include "PlayerbotAIConfig.h"

inline void ZyriaDebug(const std::string& message) {
	if (!sPlayerbotAIConfig.llmZyriaDebugLogging)
		return;

	std::ofstream logFile;
    logFile.open("zyria_llm_debug.log", std::ios::app); // Append mode
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
}

#endif // ZYRIA_DEBUG_H
