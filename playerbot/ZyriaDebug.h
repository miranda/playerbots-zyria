#ifndef ZYRIA_DEBUG_H
#define ZYRIA_DEBUG_H

#include <fstream>
#include <string>
#include <sstream>
#include <iomanip>
#include <ctime>
#include "PlayerbotAIConfig.h"

inline void ZyriaDebug(const std::string& message, const std::string& prefix = "DEBUG") {
    if (!sPlayerbotAIConfig.llmZyriaDebugLogging)
        return;

    // Get the current time
    std::time_t now = std::time(nullptr);
    std::tm* localTime = std::localtime(&now);
    
    // Format the time as [YYYY-MM-DD HH:MM:SS]
    std::ostringstream oss;
    oss << "[" << std::put_time(localTime, "%Y-%m-%d %H:%M:%S");

    std::ofstream logFile("zyria_llm_debug.log", std::ios::app);  // Open in append mode
    if (logFile.is_open()) {
        logFile << oss.str() << " ZYRIA " << prefix << "]: " << message << std::endl;  // Add timestamp
        logFile.close();
    }
}

#endif // ZYRIA_DEBUG_H
