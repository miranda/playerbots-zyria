//These methods are supposed to be called asynchronous from the main processes 'and' be greatly delayed by LLM interfernece.
//As such performance (such as opting to use regex) was not a consideration.
//And yes I used chat-gpt to write most of this. LLM for LLM code is what I call fitting.

#include "PlayerbotLLMInterface.h"

#include <iostream>
#include <string>
#include <cstring>
#include <sstream>
#include <regex>
#include <chrono>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <thread>
#include "Log/Log.h"
#include "PlayerbotAIConfig.h"
#include "PlayerbotTextMgr.h"
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma comment(lib, "ws2_32.lib")
#else
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <errno.h>
#endif

#include <vector>
#include <mutex>
#include "strategy/AiObjectContext.h"
#include "playerbot/AiFactory.h"
#include <boost/json/error.hpp>

std::string PlayerbotLLMInterface::SanitizeForJson(const std::string& input) {
    std::string sanitized;
    for (char c : input) {
        switch (c) {
        case '\"': sanitized += "\\\""; break;
        case '\\': sanitized += "\\\\"; break;
        case '\b': sanitized += "\\b"; break; 
        case '\f': sanitized += "\\f"; break; 
        case '\n': sanitized += "\\n"; break; 
        case '\r': sanitized += "\\r"; break; 
        case '\t': sanitized += "\\t"; break; 
        default:
            if (c < 0x20) {
                char buffer[7];
                snprintf(buffer, sizeof(buffer), "\\u%04x", c);
                sanitized += buffer;
            }
            else {
                sanitized += c; 
            }
        }
    }
    return sanitized;
}

inline void SetNonBlockingSocket(int sock) {
#ifdef _WIN32
    u_long mode = 1;
    if (ioctlsocket(sock, FIONBIO, &mode) != 0) {
        sLog.outError("BotLLM: Failed to set non-blocking mode on socket.");
    }
#else
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags == -1 || fcntl(sock, F_SETFL, flags | O_NONBLOCK) == -1) {
        sLog.outError("BotLLM: Failed to set non-blocking mode on socket");
    }
#endif
}

inline void RestoreBlockingSocket(int sock) {
#ifdef _WIN32
    u_long mode = 0;
    ioctlsocket(sock, FIONBIO, &mode);
#else
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags & ~O_NONBLOCK);
#endif
}

inline std::string RecvWithTimeout(int sock, int timeout_seconds, int& bytesRead) {
    char buffer[4096];
    int bufferSize = sizeof(buffer);
    std::string response;

    SetNonBlockingSocket(sock);

    auto start = std::chrono::steady_clock::now();

    while (true) {
        bytesRead = recv(sock, buffer, bufferSize - 1, 0);

        if (bytesRead > 0) {
            buffer[bytesRead] = '\0';
            response += buffer;
        }
        else if (bytesRead == -1) {
#ifdef _WIN32
            if (WSAGetLastError() == WSAEWOULDBLOCK) {
#else
            if (errno == EWOULDBLOCK || errno == EAGAIN) {
#endif
                auto now = std::chrono::steady_clock::now();
                if (std::chrono::duration_cast<std::chrono::seconds>(now - start).count() >= timeout_seconds) {
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            else {
#ifdef _WIN32
                sLog.outError("BotLLM: recv error: %s", WSAGetLastError());
#else
                sLog.outError("BotLLM: recv error: %s", strerror(errno));
#endif
                break;
            }
            }
        else {
            break;
        }
        }

    RestoreBlockingSocket(sock);

    return response;
    }

std::string PlayerbotLLMInterface::Generate(const std::string& prompt, int timeOutSeconds, int maxGenerations, std::vector<std::string> & debugLines) {
	bool debug = !debugLines.empty();

	bool evictedOld = false;
	if (sPlayerbotLLMInterface.generationCount >= maxGenerations)
	{
		if (!sPlayerbotLLMInterface.generationTimes.empty()) {
			if (debug)
				debugLines.push_back("Max generations hit. Dropping oldest.");
			
			sPlayerbotLLMInterface.generationTimes.pop_front();  // Drop oldest
			sPlayerbotLLMInterface.generationCount--;
			evictedOld = true;
		}
	}

    sPlayerbotLLMInterface.generationCount++;
    sPlayerbotLLMInterface.generationTimes.push_back(std::chrono::steady_clock::now());

    if (debug)
        debugLines.push_back("Generations start " + std::to_string(sPlayerbotLLMInterface.generationCount) + "/" + std::to_string(maxGenerations));

#ifdef _WIN32
    if (debug)
        debugLines.push_back("Initialize Winsock");

    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        if (debug)
            debugLines.push_back("WSAStartup failed");

        sLog.outError("BotLLM: WSAStartup failed");
        return "error";
    }
#endif

    ParsedUrl parsedUrl = sPlayerbotAIConfig.llmEndPointUrl;

    if (debug)
        debugLines.push_back("Resolve hostname to IP address: " + parsedUrl.hostname + " " + std::to_string(parsedUrl.port));

    struct addrinfo hints = {}, * res;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(parsedUrl.hostname.c_str(), std::to_string(parsedUrl.port).c_str(), &hints, &res) != 0) {
        if (debug)
            debugLines.push_back("Failed to resolve hostname");

        sLog.outError("BotLLM: Failed to resolve hostname");
#ifdef _WIN32
        WSACleanup();
#endif
        return "error";
    }

    if (debug)
        debugLines.push_back("Create a socket");
    int sock;
#ifdef _WIN32
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock == INVALID_SOCKET) {
        if (debug)
            debugLines.push_back("Socket creation failed");

        sLog.outError("BotLLM: Socket creation failed");
        WSACleanup();
        return "error";
    }
#else
    sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (sock < 0) {
        if (debug)
            debugLines.push_back("Socket creation failed");

        sLog.outError("BotLLM: Socket creation failed");
        freeaddrinfo(res);
        return "error";
    }
#endif

    if (debug)
        debugLines.push_back("Connect to the server");

    if (connect(sock, res->ai_addr, res->ai_addrlen) < 0) {
        if (debug)
            debugLines.push_back("Connection to server failed");

        sLog.outError("BotLLM: Connection to server failed");
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
        freeaddrinfo(res);
        return "error";
    }

    freeaddrinfo(res);

    SSL_CTX* ctx = nullptr;
    SSL* ssl = nullptr;

    if (parsedUrl.https)
    {
        // Initialize OpenSSL
        SSL_library_init();
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        const SSL_METHOD* method = TLS_client_method();
        ctx = SSL_CTX_new(method);
        if (!ctx) {
            if (debug)
                debugLines.push_back("Failed to create SSL context");
            sLog.outError("BotLLM: Failed to create SSL context");
#ifdef _WIN32
            closesocket(sock);
            WSACleanup();
#else
            close(sock);
#endif
            return "";
        }

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, sock);
        if (SSL_connect(ssl) <= 0) {
            if (debug)
                debugLines.push_back("SSL connection failed");
            sLog.outError("BotLLM: SSL connection failed");
            SSL_free(ssl);
            SSL_CTX_free(ctx);
#ifdef _WIN32
            closesocket(sock);
            WSACleanup();
#else
            close(sock);
#endif
            return "";
        }
    }

    std::ostringstream request;
    request << "POST " << parsedUrl.path << " HTTP/1.1\r\n";
    request << "Host: " << parsedUrl.hostname << "\r\n";
    request << "Content-Type: application/json\r\n";
    if (!sPlayerbotAIConfig.llmApiKey.empty())
        request << "Authorization: Bearer " << sPlayerbotAIConfig.llmApiKey << "\r\n";
    std::string body = prompt;
    request << "Content-Length: " << body.size() << "\r\n";
    request << "\r\n";
    request << body;

    if (debug)
        debugLines.push_back("Send the request" + request.str());

    bool write = parsedUrl.https ? (SSL_write(ssl, request.str().c_str(), request.str().size()) <= 0) : (send(sock, request.str().c_str(), request.str().size(), 0) < 0);
    if (write) {
        if (debug)
            debugLines.push_back("Failed to send request");
        sLog.outError("BotLLM: Failed to send request");
        
        if (parsedUrl.https)
        {
            SSL_free(ssl);
            SSL_CTX_free(ctx);
        }
#ifdef _WIN32
        closesocket(sock);
        WSACleanup();
#else
        close(sock);
#endif
        return "error";
    }

    if (debug)
        debugLines.push_back("Read the response");

    int bytesRead;
    
    std::string response = RecvWithTimeout(sock, timeOutSeconds, bytesRead);

#ifdef _WIN32
    if (bytesRead == SOCKET_ERROR) {
        if (debug)
            debugLines.push_back("Error reading response");
        sLog.outError("BotLLM: Error reading response");
    }
    closesocket(sock);
    WSACleanup();
#else
    if (bytesRead < 0) {
        if (debug)
            debugLines.push_back("Error reading response");
        sLog.outError("BotLLM: Error reading response");
    }
    close(sock);
#endif

	sPlayerbotLLMInterface.generationCount--;
	if (!evictedOld && !sPlayerbotLLMInterface.generationTimes.empty())
		sPlayerbotLLMInterface.generationTimes.pop_back();

    if (debug)
    {
        if (!response.empty())
            debugLines.push_back(response);
        else
            debugLines.push_back("Empty response");
    }

    size_t pos = response.find("\r\n\r\n");
    if (pos != std::string::npos) {
        response = response.substr(pos + 4);
        if (debug)
            debugLines.push_back(response);
    }

    return response;
}

inline std::string extractAfterPattern(const std::string& content, const std::string& startPattern) {
    std::regex pattern(startPattern);
    std::smatch match;

    if (std::regex_search(content, match, pattern)) {
        size_t start_pos = match.position() + match.length();
        return content.substr(start_pos);
    }
    else {
        return "";
    }

}

inline std::string extractBeforePattern(const std::string& content, const std::string& endPattern) {
    std::regex pattern(endPattern);
    std::smatch match;

    if (std::regex_search(content, match, pattern)) {
        size_t end_pos = match.position();

        return content.substr(0, end_pos);
    }
    else {
        return content;
    }
}

inline std::vector<std::string> splitResponse(const std::string& response, const std::string& splitPattern) {
    std::vector<std::string> result;
    
    // Special case: if using `|`, consume it completely
    if (splitPattern == "\\|") {
        std::regex pattern(splitPattern);
        std::sregex_token_iterator iter(response.begin(), response.end(), pattern, -1);
        std::sregex_token_iterator end;
        for (; iter != end; ++iter) {
            if (!iter->str().empty())  // Prevent empty splits
                result.push_back(iter->str());
        }
    } 
    else {	// Default behavior: Keep the split character (like punctuation)
        std::regex pattern(splitPattern);
        std::sregex_token_iterator iter(response.begin(), response.end(), pattern, {-1, 0});
        std::sregex_token_iterator end;
        for (; iter != end; ++iter) {
            result.push_back(iter->str());
        }
    }

    if (result.empty())
        result.push_back(response);

    return result;
}

std::vector<std::string> PlayerbotLLMInterface::ParseResponse(const std::string& response, const std::string& startPattern, const std::string& endPattern, const std::string& deletePattern, const std::string& splitPattern, std::vector<std::string>& debugLines)
{
    bool debug = !(debugLines.empty());
    uint32 startCursor = 0;
    uint32 endCursor = 0;

    std::string actualResponse = response;

    if (debug)
        debugLines.push_back("start pattern:" + startPattern);
    
    actualResponse = extractAfterPattern(actualResponse, startPattern);

    PlayerbotTextMgr::ReplaceAll(actualResponse, R"(\")", "'");

    if (debug)
    {
        debugLines.push_back(!actualResponse.empty() ? actualResponse : "Empty response");
        debugLines.push_back("end pattern:" + endPattern);
    }

    actualResponse = extractBeforePattern(actualResponse, endPattern);

    if (debug)
    {
        debugLines.push_back(!actualResponse.empty() ? actualResponse : "Empty response");
        debugLines.push_back("delete pattern:" + deletePattern);
    }

	if (!deletePattern.empty())
	{
		std::regex regexPattern(deletePattern);
		actualResponse = std::regex_replace(actualResponse, regexPattern, "");
	}

    if (debug)
    {
        debugLines.push_back(!actualResponse.empty() ? actualResponse : "Empty response");
        debugLines.push_back("split pattern:" + splitPattern);
    }

    std::vector<std::string> responses = splitResponse(actualResponse, splitPattern);   

    if (debug)
        debugLines.insert(debugLines.end(), responses.begin(), responses.end());

    return responses;
}

std::pair<std::vector<std::string>, boost::json::object> PlayerbotLLMInterface::ParseResponseV2(const std::string& response, std::vector<std::string>& debugLines)
{
    bool debug = !(debugLines.empty());

    std::string actualResponse;
    boost::json::object zyria_data;

    if (!sPlayerbotAIConfig.llmUseZyriaServer)
    {
        if (debug)
            debugLines.push_back("[V2] Called but ZyriaServer is not enabled");
        return { {}, {} };
    }

    try
    {
        boost::json::value jv = boost::json::parse(response);
        boost::json::object obj = jv.as_object();

        if (obj.contains("text") && obj["text"].is_string())
            actualResponse = obj["text"].as_string().c_str();
        else
        {
            if (debug)
                debugLines.push_back("Missing or invalid 'text' field");
            return { {}, {} };
        }

        if (obj.contains("zyria_data") && obj["zyria_data"].is_object())
            zyria_data = obj["zyria_data"].as_object();

        if (debug)
        {
            debugLines.push_back("Parsed text: " + actualResponse);
            debugLines.push_back("Extracted zyria_data: " + boost::json::serialize(zyria_data));
        }
    }
	catch (const boost::system::system_error& e)
	{
		if (debug)
			debugLines.push_back("Boost.JSON parse error: " + std::string(e.what()));
		return { {}, {} };
	}

    std::vector<std::string> responses = splitResponse(actualResponse, "\\|");

    if (debug)
        debugLines.insert(debugLines.end(), responses.begin(), responses.end());

    return { responses, zyria_data };
}

void PlayerbotLLMInterface::LimitContext(std::string& context, int currentLength, std::string knownName)
{
    if (!sPlayerbotAIConfig.llmContextLength)
        return;

    // Optimize space usage before checking length
    CollapseSpaces(context);

    uint32_t maxLen = sPlayerbotAIConfig.llmContextLength;
    if (static_cast<uint32_t>(currentLength) <= maxLen)
        return;

    uint32_t cutNeeded = currentLength - maxLen;

    if (cutNeeded >= context.size())
    {
        context.clear();
        return;
    }

    size_t trimPos = std::string::npos;

    // 1️⃣ **Check for known NPC name first**
    if (!knownName.empty())
    {
        std::string namePattern = "\\b" + knownName + ":";  // Ensure full name is matched
        size_t foundPos = context.find(namePattern);
        
        if (foundPos != std::string::npos && foundPos >= cutNeeded)
        {
            trimPos = foundPos;
        }
    }

    // 2️⃣ **Fallback: Find dialog boundary with regex if no known name match**
    if (trimPos == std::string::npos)
    {
        std::regex dialogRegex(R"((?:^|\s)([A-Za-z]+):(\S))"); // Matches "Name:word" format
        std::smatch match;
        std::string::const_iterator searchStart = context.cbegin();

        while (std::regex_search(searchStart, context.cend(), match, dialogRegex))
        {
            size_t matchStart = static_cast<size_t>(match.position());
            size_t absolutePos = static_cast<size_t>(searchStart - context.cbegin()) + matchStart;

            if (absolutePos >= cutNeeded)
            {
                trimPos = absolutePos;
                break;
            }

            searchStart = match.suffix().first; // Move past the current match
        }
    }

    // 3️⃣ **Trim context based on the identified position**
    if (trimPos == std::string::npos)
    {
        context.clear();
    }
    else
    {
        context = context.substr(trimPos);
    }

}

void PlayerbotLLMInterface::CollapseSpaces(std::string& str)
{
	// Remove consecutive spaces
	str.erase(std::unique(str.begin(), str.end(), [](char a, char b) {
		return a == ' ' && b == ' ';
	}), str.end());

	// Trim leading and trailing spaces (optional)
	if (!str.empty() && str.front() == ' ')
		str.erase(str.begin());
	if (!str.empty() && str.back() == ' ')
		str.pop_back();
}
