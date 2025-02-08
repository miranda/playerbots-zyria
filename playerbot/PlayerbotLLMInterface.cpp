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
#include <thread>
#include "Log/Log.h"
#include "PlayerbotAIConfig.h"
#include "PlayerbotTextMgr.h"
#endif

#include <vector>
#include "ZyriaDebug.h"

// Helper function to trim whitespace from a string
/*
static std::string trim(const std::string& str) {
    std::string trimmed = str;
    trimmed.erase(trimmed.begin(), std::find_if(trimmed.begin(), trimmed.end(), [](unsigned char ch) {
        return !std::isspace(ch);
    }));
    trimmed.erase(std::find_if(trimmed.rbegin(), trimmed.rend(), [](unsigned char ch) {
        return !std::isspace(ch);
    }).base(), trimmed.end());
    return trimmed;
}
*/

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
	//ZyriaDebug("PlayerbotLLMInterface sent prompt: " + prompt);

    if (sPlayerbotLLMInterface.generationCount > maxGenerations)
    {
        if (debug)
            debugLines.push_back("Maxium generations reached " + std::to_string(sPlayerbotLLMInterface.generationCount) + "/" + std::to_string(maxGenerations));
        return {};
    }

    sPlayerbotLLMInterface.generationCount++;

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
    else {
        // Default behavior: Keep the split character (like punctuation)
        std::regex pattern(splitPattern);
        std::sregex_token_iterator iter(response.begin(), response.end(), pattern, {-1, 0});
        std::sregex_token_iterator end;
        for (; iter != end; ++iter) {
            result.push_back(iter->str());
        }
    }

    // If result is empty, return the original string to prevent loss of text
    if (result.empty())
        result.push_back(response);

    return result;
}
/*
inline std::vector<std::string> splitResponse(const std::string& response, const std::string& splitPattern) {
    std::vector<std::string> result;
    std::regex pattern(splitPattern);
    std::smatch match;
    
    std::sregex_iterator begin(response.begin(), response.end(), pattern);
    std::sregex_iterator end;
    for (auto it = begin; it != end; ++it) {
        result.push_back(it->str());
    }

    if(result.empty())
        result.push_back(response);

    return result;
}
*/

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

/*
void PlayerbotLLMInterface::LimitContext(std::string& context, int currentLength)
{
    if (!sPlayerbotAIConfig.llmContextLength)
        return;

    uint32_t maxLen = sPlayerbotAIConfig.llmContextLength;
    if (static_cast<uint32_t>(currentLength) <= maxLen)
        return;

    uint32_t cutNeeded = currentLength - maxLen;

    if (cutNeeded >= context.size())
    {
        ZyriaDebug("DEBUG: LimitContext: context cleared (cutNeeded >= context.size()).");
        context.clear();
        return;
    }

    // Find dialog boundaries
    ZyriaDebug("DEBUG: LimitContext: Attempting to trim context at dialog boundary...");
    std::regex dialogRegex(R"((?:^|\s)([A-Za-z]+):(\S))"); // Matches "Name:word" with leading space or start of string
    std::smatch match;
    std::string::const_iterator searchStart = context.cbegin();

    size_t trimPos = std::string::npos;
    while (std::regex_search(searchStart, context.cend(), match, dialogRegex))
    {
        size_t matchStart = static_cast<size_t>(match.position());
        size_t absolutePos = static_cast<size_t>(searchStart - context.cbegin()) + matchStart;

        ZyriaDebug("DEBUG: Found dialog line at absolutePos = " + std::to_string(absolutePos) + ", match = '" + match.str() + "'");

        if (absolutePos >= cutNeeded)
        {
            trimPos = absolutePos;
            break;
        }

        searchStart = match.suffix().first; // Move past the current match
    }

    if (trimPos == std::string::npos)
    {
        // If no valid dialog boundary is found, clear the context (this should never happen)
        ZyriaDebug("DEBUG: No valid dialog boundary found. Context cleared.");
        context.clear();
    }
    else
    {
        // Trim the context at the identified boundary
        size_t oldSize = context.size();
        context = context.substr(trimPos);

        ZyriaDebug("DEBUG: Context trimmed at dialog boundary (trimPos = " + std::to_string(trimPos) + "). Old size: " +
                  std::to_string(oldSize) + ", new size: " + std::to_string(context.size()) +
                  ", new text: '" + context + "'");
    }
}
*/

void PlayerbotLLMInterface::LimitContext(std::string& context, int currentLength)
{
    if (!sPlayerbotAIConfig.llmContextLength)
        return;

    uint32_t maxLen = sPlayerbotAIConfig.llmContextLength;
    uint32_t trimPercentage = sPlayerbotAIConfig.llmContextTrimAmount;

    // Only proceed if the context exceeds maxLen
    if (static_cast<uint32_t>(currentLength) <= maxLen)
        return;

    // Calculate the minimum trim size as a percentage of maxLen
    uint32_t trimSize = static_cast<uint32_t>(maxLen * (static_cast<float>(trimPercentage) / 100.0f));
    uint32_t cutNeeded = currentLength - maxLen;

    // Ensure the cut size is at least trimSize
    uint32_t cutSize = std::max(cutNeeded, trimSize);

    if (cutSize >= context.size())
    {
        //ZyriaDebug("DEBUG: LimitContext: context cleared (cutSize >= context.size()).");
        context.clear();
        return;
    }

    // Find dialog boundaries
    //ZyriaDebug("DEBUG: LimitContext: Attempting to trim context at dialog boundary...");
    std::regex dialogRegex(R"((?:^|\s)([A-Za-z]+):(\S))"); // Matches "Name:word" with leading space or start of string
    std::smatch match;
    std::string::const_iterator searchStart = context.cbegin();

    size_t trimPos = std::string::npos;
    while (std::regex_search(searchStart, context.cend(), match, dialogRegex))
    {
        size_t matchStart = static_cast<size_t>(match.position());
        size_t absolutePos = static_cast<size_t>(searchStart - context.cbegin()) + matchStart;

        //ZyriaDebug("DEBUG: Found dialog line at absolutePos = " + std::to_string(absolutePos) + ", match = '" + match.str() + "'");

        if (absolutePos >= cutSize)
        {
            trimPos = absolutePos;
            break;
        }

        searchStart = match.suffix().first; // Move past the current match
    }

    if (trimPos == std::string::npos)
    {
        // If no valid dialog boundary is found, clear the context
        //ZyriaDebug("DEBUG: No valid dialog boundary found. Context cleared.");
        context.clear();
    }
    else
    {
        // Trim the context at the identified boundary
        size_t oldSize = context.size();
        context = context.substr(trimPos);

        //ZyriaDebug("DEBUG: Context trimmed at dialog boundary (trimPos = " + std::to_string(trimPos) + "). Old size: " +
        //          std::to_string(oldSize) + ", new size: " + std::to_string(context.size()) +
        //          ", new text: '" + context + "'");
    }
}
