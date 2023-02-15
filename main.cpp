#include <iostream>
#include <string>
#include <map>
#include "array"
#include <thread>
#include <mutex>
#include "fmt/core.h"
#include <fmt/chrono.h>
#include "KalkanCrypt.h"

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN		// Exclude rarely-used stuff from Windows headers
#include <windows.h>
#else

#include <dlfcn.h>

#endif

#include "httplib/httplib.h"


using namespace std;

const int CERT_LENGTH = 32768;
const int OUT_CERT_LENGTH = 65536;
const int ERROR_LENGTH = OUT_CERT_LENGTH;

using KC_GetFunctionList1 = int (*)(stKCFunctionsType **);
using stringMapT = map<string, string>;


string TSA_URL = "http://tsp.pki.gov.kz:80";
//string TSA_URL = "http://test.pki.gov.kz/tsp/";
const string OSCP_LINK = "http://ocsp.pki.gov.kz/";
//const string OSCP_LINK = "http://test.pki.gov.kz/ocsp/";
const string CRL_F = "certs/nca_gost2022_test.crl";

enum class kc_use_t {
    USE_OCSP,
    USE_CRL
};

////////////////////////Functions ------------------------>>>>>>>>>>>>>>>>>>>>>

static inline string ltrim(string s) {
    s.erase(s.begin(), find_if(s.begin(), s.end(), [](unsigned char ch) {
        return !isspace(ch);
    }));
    return s;
}

static inline string rtrim(string s) {
    s.erase(find_if(s.rbegin(), s.rend(), [](unsigned char ch) {
        return !isspace(ch);
    }).base(), s.end());
    return s;
}

// trim from both ends (copy)
static inline string trim(const string &s) {
    return ltrim(rtrim(s));
}

static inline auto convert2pem(string str) {
    const string begin_text = "-----BEGIN CERTIFICATE-----";
    if (str.find(begin_text) != string::npos) {
        return str;
    }
    str.erase(remove(str.begin(), str.end(), '\n'), str.end());
    str.erase(remove(str.begin(), str.end(), '\r'), str.end());
    replace(str.begin(), str.end(), ' ', '+');
    string result{begin_text + "\n"};
    for (int i = 0; i < str.size(); i += 64) {
        result += str.substr(i, 64) + "\n";
    }
    result += "-----END CERTIFICATE-----\n";
    return result;
}

static inline string replaceAll(string str, const string &from, const string &to) {
    size_t start_pos = 0;
    while ((start_pos = str.find(from, start_pos)) != string::npos) {
        str.replace(start_pos, from.length(), to);
        start_pos += to.length(); // Handles case where 'to' is a substring of 'from'
    }
    return str;
}

static inline string toJson(const stringMapT &mp) {
    string rez;
    int i = 1;
    for (auto const &[k, v]: mp) {
        auto c = i < mp.size() ? ",\n" : "";
        rez += fmt::format(R"("{}": "{}"{})", k, replaceAll(v, "\"", "\\\""), c);
        i++;
    }
    return fmt::format("{{{}}}", rez);
}

static inline void compareS(const string &s1, const string &s2) {
    auto size = (s1.size() < s2.size()) ? s1.size() : s2.size();
    for (int x = 0; x < size; x++) {
        if (s1.at(x) != s2.at(x)) {
            cout << "\"" << s1.at(x) << "\" != \"" << s2.at(x) << "\" " << x << "\n";
        }
    }
}

stringMapT configs{};

stringMapT load_conf() {
    string line;
    ifstream myfile("config.ini");
    if (!myfile.is_open()) return {};
    while (!myfile.eof()) {
        getline(myfile, line);
        line = trim(line);
        if (line.substr(0, 1) == "#" || line.substr(0, 1) == ";") continue;
        string::size_type pos = line.find('=', 0);
        if (pos == string::npos) continue;
        string key = trim(line.substr(0, pos));
        string value = trim(line.substr(pos + 1));
        configs[key] = value;
    }
    myfile.close();
    return configs;
}

string get_conf(const string &key, const string &deflt = "") {
    string res;
    auto it = configs.find(key);
    if (it != configs.end())
        res = it->second;
    else
        res = deflt;
    return res;
}

#ifndef _WIN32
void *handle{};
#else
HMODULE handle = nullptr;
#endif

mutex g_i_mutex{};

KC_GetFunctionList1 lib_funcList{};
stKCFunctionsType *kc_funcs{};

class MySign {
public:

    static void init_handle(bool loadStorage = false) {
#ifndef _WIN32
        dlerror();    /* Clear all existing error */
        handle = dlopen("libkalkancryptwr-64.so", RTLD_LAZY);
        if (!handle) {
            fmt::print(stderr, "Error: {}\n", dlerror());
            exit(EXIT_FAILURE);
        }
#else
        handle = LoadLibrary(L"KalkanCrypt.dll");
        if (!handle) {
            fmt::print(stderr, "Error: {}\n", ::GetLastError());
            exit(EXIT_FAILURE);
        }
#endif
#ifndef _WIN32
        dlerror();    /* Clear all existing error */
        lib_funcList = reinterpret_cast<KC_GetFunctionList1> (dlsym(handle, "KC_GetFunctionList"));
        auto error = dlerror();
        if (error != nullptr) {
            fmt::print(stderr, "{}\n", error);
            exit(EXIT_FAILURE);
        }
#else
        lib_funcList = reinterpret_cast<KC_GetFunctionList1> (GetProcAddress(handle, "KC_GetFunctionList"));
        if (lib_funcList == nullptr) {
            fmt::print(stderr, "error loading KC_GetFunctionList!!!\n");
            exit(EXIT_FAILURE);
        }
#endif

        lib_funcList(&kc_funcs);
        kc_funcs->KC_Init();
        kc_funcs->KC_TSASetUrl(TSA_URL.data());

        if (loadStorage && !storage_load(get_conf("cert"), get_conf("cert_passwd"))) { exit(EXIT_FAILURE); }
    }

public:

    static bool storage_load(string container, string password, int storage = KCST_PKCS12) {
        const lock_guard<mutex> lock(g_i_mutex);
        string alias;
        auto containerLen = container.size();
        alias = "";
        auto passwordLen = password.size();
        kc_funcs->KC_LoadKeyStore(storage, password.data(), passwordLen, container.data(), containerLen, alias.data());
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        auto rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &errLen);
        if (rv > 0) {
            fmt::print(stderr, "Error: {:X}:\n{}\n", rv, string(err_str));
            return false;
        }
        fmt::print("Alias: {}\n", alias);
        return true;
    }

    static auto loadCrtFromBuffer(string &buffer, int flags = KC_CERT_B64) {
        const lock_guard<mutex> lock(g_i_mutex);
        auto bufferLength = buffer.size();
        kc_funcs->X509LoadCertificateFromBuffer(reinterpret_cast<unsigned char *>(buffer.data()), bufferLength, flags);
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        auto rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &errLen);
        if (rv > 0) {
            fmt::print(stderr, "Error: {:X}:\n{}\n", rv, string(err_str));
            return false;
        }
        return true;
    }

    static auto showCert() {
        const lock_guard<mutex> lock(g_i_mutex);
//    int kalkanFlags = KC_SIGN_DRAFT;
        int kalkanFlags = 0x00000000;
        int outCertLenInternal = CERT_LENGTH;
        char outCertInternal[CERT_LENGTH];
        string alias;
        kc_funcs->X509ExportCertificateFromStore(alias.data(), kalkanFlags, outCertInternal, &outCertLenInternal);
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        auto rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &errLen);
        if (rv > 0) {
            fmt::print(stderr, "Error: {:X}:\n{}\n", rv, string(err_str));
            return string("Error");
        } else {
            fmt::print("{}\n", string(outCertInternal));
        }
        return string{outCertInternal};
    }

    static auto certInfo(string &inCert) {
        const lock_guard<mutex> lock(g_i_mutex);
        size_t inCertLength = inCert.size();
        constexpr int outLength = 2048;
        int OutDataLength;
        char OutData[outLength];
        stringMapT rzv{};
        array<unsigned int, 27> cert_props = {KC_CERTPROP_ISSUER_COUNTRYNAME, KC_CERTPROP_ISSUER_SOPN,
                                              KC_CERTPROP_ISSUER_LOCALITYNAME, KC_CERTPROP_ISSUER_ORG_NAME,
                                              KC_CERTPROP_ISSUER_ORGUNIT_NAME, KC_CERTPROP_ISSUER_COMMONNAME,
                                              KC_CERTPROP_SUBJECT_COUNTRYNAME, KC_CERTPROP_SUBJECT_SOPN,
                                              KC_CERTPROP_SUBJECT_LOCALITYNAME, KC_CERTPROP_SUBJECT_COMMONNAME,
                                              KC_CERTPROP_SUBJECT_GIVENNAME, KC_CERTPROP_SUBJECT_SURNAME,
                                              KC_CERTPROP_SUBJECT_SERIALNUMBER, KC_CERTPROP_SUBJECT_EMAIL,
                                              KC_CERTPROP_SUBJECT_ORG_NAME, KC_CERTPROP_SUBJECT_ORGUNIT_NAME,
                                              KC_CERTPROP_SUBJECT_BC, KC_CERTPROP_SUBJECT_DC,
                                              KC_CERTPROP_NOTBEFORE,
                                              KC_CERTPROP_NOTAFTER, KC_CERTPROP_KEY_USAGE,
                                              KC_CERTPROP_EXT_KEY_USAGE,
                                              KC_CERTPROP_AUTH_KEY_ID, KC_CERTPROP_SUBJ_KEY_ID,
                                              KC_CERTPROP_CERT_SN,
                                              KC_CERTPROP_SUBJECT_DN,
                                              KC_CERTPROP_SIGNATURE_ALG};
        array<string, 27> cert_props_str = {"KC_CERTPROP_ISSUER_COUNTRYNAME", "KC_CERTPROP_ISSUER_SOPN",
                                            "KC_CERTPROP_ISSUER_LOCALITYNAME", "KC_CERTPROP_ISSUER_ORG_NAME",
                                            "KC_CERTPROP_ISSUER_ORGUNIT_NAME",
                                            "KC_CERTPROP_ISSUER_COMMONNAME",
                                            "KC_CERTPROP_SUBJECT_COUNTRYNAME", "KC_CERTPROP_SUBJECT_SOPN",
                                            "KC_CERTPROP_SUBJECT_LOCALITYNAME",
                                            "KC_CERTPROP_SUBJECT_COMMONNAME",
                                            "KC_CERTPROP_SUBJECT_GIVENNAME", "KC_CERTPROP_SUBJECT_SURNAME",
                                            "KC_CERTPROP_SUBJECT_SERIALNUMBER", "KC_CERTPROP_SUBJECT_EMAIL",
                                            "KC_CERTPROP_SUBJECT_ORG_NAME",
                                            "KC_CERTPROP_SUBJECT_ORGUNIT_NAME",
                                            "KC_CERTPROP_SUBJECT_BC", "KC_CERTPROP_SUBJECT_DC",
                                            "KC_CERTPROP_NOTBEFORE", "KC_CERTPROP_NOTAFTER",
                                            "KC_CERTPROP_KEY_USAGE", "KC_CERTPROP_EXT_KEY_USAGE",
                                            "KC_CERTPROP_AUTH_KEY_ID", "KC_CERTPROP_SUBJ_KEY_ID",
                                            "KC_CERTPROP_CERT_SN", "KC_CERTPROP_SUBJECT_DN",
                                            "KC_CERTPROP_SIGNATURE_ALG"};

        for (int i = 0; i < cert_props.size(); i++) {
            OutDataLength = outLength;
            auto rv = kc_funcs->X509CertificateGetInfo(inCert.data(), inCertLength, cert_props[i],
                                                       reinterpret_cast<unsigned char *>(OutData), &OutDataLength);
            if (rv > 0) {
                fmt::print("\n");
                rzv.emplace(cert_props_str.at(i), string{});
            } else {
                fmt::print("{}:\n {}\n", cert_props_str[i], string{OutData});
                rzv.emplace(cert_props_str.at(i), string{OutData});
            }
        }
        return rzv;
    }

    static auto checkSignedData(string &inData, string &inOutSign,
                                int flags_sign = KC_SIGN_CMS | KC_IN_BASE64 | KC_OUT_BASE64) {
        const lock_guard<mutex> lock(g_i_mutex);
        string alias;
        int outDataLength = OUT_CERT_LENGTH, outVerifyInfoLength = OUT_CERT_LENGTH,
                outVerifyCertLength = OUT_CERT_LENGTH;
        if ((flags_sign & KC_DETACHED_DATA) == KC_DETACHED_DATA)
            outDataLength = 0;
        char outData[OUT_CERT_LENGTH];
        char outVerifyInfo[OUT_CERT_LENGTH];
        char outVerifyCert[OUT_CERT_LENGTH];
        stringMapT result{};
        kc_funcs->VerifyData(alias.data(), flags_sign, inData.data(), inData.size(),
                             reinterpret_cast<unsigned char *>(inOutSign.data()),
                             inOutSign.size(), outData, &outDataLength, outVerifyInfo,
                             &outVerifyInfoLength, 0, outVerifyCert, &outVerifyCertLength);
        char err_str[ERROR_LENGTH];
        int outErrorStringLen = ERROR_LENGTH;
        auto rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &outErrorStringLen);
        if (rv > 0) { fmt::print(stderr, "Error: {:X}\n{}\n\n", rv, string{err_str}); }
        else {
            fmt::print("{}\n{}\n{}\n", string{outVerifyCert}, string{outVerifyInfo},
                       string{outData});
            result.emplace("outVerifyCert", string{outVerifyCert});
            result.emplace("outVerifyInfo", string{outVerifyInfo});
            result.emplace("outData", string{outData});
        }
        return result;
    }


    static auto signData(string &inData, string &inSign, int flags_sign) {
/*      fmt::print("Выберите тип подписи:");
1) CMS-подпись. Без метки времени      KC_SIGN_CMS | KC_IN_PEM | KC_OUT_PEM;
2) CMS-подпись. С меткой времени       KC_SIGN_CMS | KC_IN_PEM | KC_OUT_PEM | KC_WITH_TIMESTAMP;
3) Сырая подпись (DraftSign) доп. вход. данные в BASE64    KC_SIGN_DRAFT | KC_IN_PEM | KC_OUT_BASE64 | KC_IN2_BASE64;
4) Данные хранятся отдельно            KC_SIGN_CMS | KC_IN_PEM | KC_OUT_PEM | KC_DETACHED_DATA;
5) Подпись данных в формате BASE64     KC_SIGN_CMS | KC_IN_BASE64 | KC_OUT_BASE64 ;*/

        const lock_guard<mutex> lock(g_i_mutex);
        string alias;
        int outSignLength = 50000 + 2 * inData.size();
        std::vector<char> outSign(outSignLength);
//    auto outSign = make_unique<char[]>(outSignLength);
        kc_funcs->SignData(alias.data(), flags_sign, inData.data(), inData.size(),
                           reinterpret_cast<unsigned char *>(inSign.data()), inSign.size(),
                           reinterpret_cast<unsigned char *>(outSign.data()), &outSignLength);
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        unsigned long rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &errLen);
        if (rv > 0) {
            fmt::print(stderr, "Error: {:X}:\n{}\n", rv, string{err_str});
            return string{"Error"};
        } else { fmt::print("\n{}\n", string{outSign.data()}); }
        return string{outSign.data(), static_cast<size_t>(outSignLength)};
    }

    static auto signDataXML(string &inXMLData, bool with_ts = false) {
        const lock_guard<mutex> lock(g_i_mutex);
        string alias;
        string signNodeId;
        string parentNameSpace;
        string parentSignNode;
        int outXMLSignLength = inXMLData.size() + 50000;
        vector<char> outXMLSign(outXMLSignLength);
        int flags_xml = with_ts ? KC_WITH_TIMESTAMP : 0x0;
        kc_funcs->SignXML(alias.data(), flags_xml, inXMLData.data(), inXMLData.size(),
                          reinterpret_cast<unsigned char *>(outXMLSign.data()), &outXMLSignLength,
                          signNodeId.data(), parentSignNode.data(), parentNameSpace.data());
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        unsigned long rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &errLen);
        if (rv > 0) {
            fmt::print(stderr, "Error: {:X}:\n{}\n", rv, string{err_str});
            return string{"Error"};
        }
        kc_funcs->KC_XMLFinalize();
        fmt::print("\n{}\n", string(outXMLSign.data()));
        return string(outXMLSign.data());
    }

    static auto checkXMLSign(string &inXMLSign) {
        const lock_guard<mutex> lock(g_i_mutex);
        string alias;
        int inXMLSignLength = inXMLSign.size();
        constexpr int verifyInfoLen = 8192;
        int outVerifyInfoLen = verifyInfoLen;
        char outVerifyInfo[verifyInfoLen];
        kc_funcs->VerifyXML(alias.data(), 0, inXMLSign.data(), inXMLSignLength, &outVerifyInfo[0],
                            &outVerifyInfoLen);
        int errLen1 = ERROR_LENGTH;
        char err_str1[ERROR_LENGTH];
        unsigned long rv = kc_funcs->KC_GetLastErrorString(&err_str1[0], &errLen1);
        if (rv > 0) {
            fmt::print(stderr, "\nVerifyXML Error: {:X}:\n{}\n", rv, string{err_str1});
            return string{"Error"};
        } else { fmt::print("\n{}\n", string{outVerifyInfo}); }
        return string{outVerifyInfo};
    }

    static auto getCertFromCMS(string &inCMS, int flags_check = KC_IN_BASE64 | KC_OUT_BASE64) {
        const lock_guard<mutex> lock(g_i_mutex);
        int inCMSLength = inCMS.size();
        int outCertFromCMSLength = CERT_LENGTH;
        char outCertFromCMS[CERT_LENGTH];
        int flags = KC_SIGN_CMS | flags_check;
        int inSignId = 1;
        kc_funcs->KC_GetCertFromCMS(inCMS.data(), inCMSLength, inSignId, flags, &outCertFromCMS[0],
                                    &outCertFromCMSLength);
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        auto rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &errLen);
        if (rv > 0) {
            fmt::print(stderr, "Error: {:X}:\n{}\n", rv, string(err_str));
            return string{"Error"};
        } else { fmt::print("{}\n", string{outCertFromCMS}); }
        return string(outCertFromCMS);
    }

    static auto getCertFromXML(const string &inXMLSign) {
        const lock_guard<mutex> lock(g_i_mutex);
        int inXMLSignLength = inXMLSign.size();
        int outCertFromXMLLength = 32768;
        char outCertFromXML[32768];
        int inSignId = 1;
        kc_funcs->KC_getCertFromXML(inXMLSign.data(), inXMLSignLength, inSignId, &outCertFromXML[0],
                                    &outCertFromXMLLength);
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        unsigned long rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &errLen);
        if (rv > 0) {
            fmt::print(stderr, "Library Init error: {:X}:\n{}\n", rv, string(err_str));
            return string{"Error"};
        } else { fmt::print("{}\n", string(outCertFromXML)); }
        return string(outCertFromXML);
    }

    static auto getTimeFromSign(string &inData, int flags_check = KC_IN_BASE64 | KC_OUT_BASE64) {
        const lock_guard<mutex> lock(g_i_mutex);
        time_t OutDateTime;
        int flags = KC_SIGN_CMS | flags_check | KC_WITH_TIMESTAMP;
//        cout << flags << endl;
        int inDataLength = inData.size();
        kc_funcs->KC_GetTimeFromSig(inData.data(), inDataLength, flags, 0, &OutDateTime);
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        unsigned long rv = kc_funcs->KC_GetLastErrorString(&err_str[0], &errLen);
        string result{};
        if (rv > 0) {
            fmt::print(stderr, "Error: {:X}:\n{}\n", rv, string{err_str});
            return string{"Error"};
        } else {
            result = fmt::format("{:%Y-%m-%d %H:%M:%S}", fmt::localtime(OutDateTime));
            fmt::print("\nВремя подписи: {}\n", result);
        }
        return result;
    }


//    type=1: KC_USE_OCSP; 2: KC_USE_CRL
    static auto checkCert(string &inCert, kc_use_t type = kc_use_t::USE_OCSP) {
        const lock_guard<mutex> lock(g_i_mutex);
        int flags, second_flag = 0;
        string validPath;
        if (type == kc_use_t::USE_OCSP) {
            flags = KC_USE_OCSP;
            validPath = OSCP_LINK;
        } else {
            flags = KC_USE_CRL;
            validPath = CRL_F;
        }
        constexpr int verifyInfoLen = 8192;
        int outInfoLen = verifyInfoLen;
        char outInfo[verifyInfoLen];
        int inCertLength = inCert.size();
        int getRespLength = verifyInfoLen;
        char getRes[verifyInfoLen];
        kc_funcs->X509ValidateCertificate(inCert.data(), inCertLength, flags, validPath.data(), 0,
                                          outInfo, &outInfoLen, second_flag, getRes, &getRespLength);
        int errLen = ERROR_LENGTH;
        char err_str[ERROR_LENGTH];
        unsigned long rv = kc_funcs->KC_GetLastErrorString(err_str, &errLen);
        string result("Error");
        if (rv > 0) {
            fmt::print(stderr, "Error: {:X}:\n{}\n", rv, string{err_str});
        } else {
            result = replaceAll(outInfo, "\r\n", ";");
            replace(result.begin(), result.end(), '\r', ';');
            replace(result.begin(), result.end(), '\n', ';');
            result.erase(remove(result.begin(), result.end(), '\t'), result.end());
            fmt::print("{}\n", result);
        }
        return result;
    }

private:


};

using namespace httplib;

template<typename F>
struct privDefer {
    F f;

    explicit privDefer(F f) : f(f) {}

    ~privDefer() { f(); }
};

template<typename F>
privDefer<F> defer_func(F f) {
    return privDefer<F>(f);
}

#define DEFER_1(x, y) x##y
#define DEFER_2(x, y) DEFER_1(x, y)
#define DEFER_3(x)    DEFER_2(x, __COUNTER__)
#define defer(code)   auto DEFER_3(_defer_) = defer_func([&](){code;})


int main() {

    load_conf();

    MySign::init_handle();

    defer (kc_funcs->KC_XMLFinalize(); kc_funcs->KC_Finalize());
#ifndef _WIN32
    defer(dlclose(handle); fmt::print("Closing handle ----->\n"););
#else
    SetConsoleCP(65001);
    SetConsoleOutputCP(65001);
    defer(FreeLibrary(handle); fmt::print("Closing handle ----->\n"););
#endif

    Server svr;

    svr.Post("/x509/info", [](const Request &req, Response &res) {
        stringMapT r{};
        if (req.has_param("cert")) {
            auto cert = req.get_param_value("cert");
            auto pem_c = convert2pem(cert);
            r = MySign::certInfo(pem_c);
        }
        res.set_content(toJson(r), "application/json");
    });

    svr.Post("/x509/test", [](const Request &req, Response &res) {
        stringMapT r{};
        if (req.has_param("cert")) {
            auto cert = req.get_param_value("cert");
            auto pem_c = convert2pem(cert);
            auto inf = MySign::checkCert(pem_c);
            r["result"] = inf;
        }
        res.set_content(toJson(r), "application/json");
    });

    svr.set_error_handler([](const auto &req, auto &res) {

        stringMapT r{{"result", fmt::format("Error Status: {}", res.status)}};
        res.set_content(toJson(r), "application/json");
    });


    svr.set_logger([](const auto &req, const auto &res) {
        string host_address = req.has_header("Host") ? req.get_header_value("Host") : "";
        fmt::print("[{:%Y-%m-%d %H:%M:%S}] [{}] [{}] [{}] -> {}{} ({})\n", chrono::system_clock::now(),
                   req.remote_addr, req.method, res.version, host_address, req.path, res.status);

    });

    svr.Get(R"(/numbers/(\d+))", [&](const Request &req, Response &res) {
        auto numbers = req.matches[1];
        fmt::print("{}\n", numbers.str());
        res.set_content(numbers, "text/plain");
    });

    svr.Get("/hi", [](const Request &req, Response &res) {
        fmt::print("start!!!!!\n");
        this_thread::sleep_for(chrono::milliseconds(24));
        auto cert = "12121212121";
        auto pem_c = convert2pem(cert);
        auto inf = MySign::checkCert(pem_c);
        fmt::print("end!!!!!\n");
        res.set_content("Hello World!", "text/plain");
    });

//    Keep-Alive connection
//Sets the maximum number of requests that can be served through one keep-alive connection.
    svr.set_keep_alive_max_count(300); // Default is 5
//Limits the maximum time during which requests can be processed through one keep-alive connection.
//After this time is reached, the connection is closed following the subsequent request processing.
    svr.set_keep_alive_timeout(75);  // Default is 5

//    Timeout
//    svr.set_read_timeout(5, 0); // 5 seconds
//    svr.set_write_timeout(5, 0); // 5 seconds
//    svr.set_idle_interval(0, 100000); // 100 milliseconds

//    Set maximum payload length for reading a request body
    svr.set_payload_max_length(1024 * 1024 * 512); // 512MB

//    std::cout << get_conf("host") << "\n" << get_conf("port")<< "\n";
    fmt::print("Starting http srv: {}:{}/\n", get_conf("host"), stoi(get_conf("port")));
    svr.listen(get_conf("host"), stoi(get_conf("port")));


    return 0;
}
