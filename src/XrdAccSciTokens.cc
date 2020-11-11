
#include "XrdAcc/XrdAccAuthorize.hh"
#include "XrdOuc/XrdOucEnv.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSys/XrdSysLogger.hh"
#include "XrdVersion.hh"

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include <sstream>
#include <unordered_map>
#include <tuple>

#include "INIReader.h"
#include "picojson.h"

#include "scitokens/scitokens.h"
#include "XrdSciTokensHelper.hh"

// The status-quo to retrieve the default object is to copy/paste the
// linker definition and invoke directly.
static XrdVERSIONINFODEF(compiledVer, XrdAccTest, XrdVNUMBER, XrdVERSION);
extern XrdAccAuthorize *XrdAccDefaultAuthorizeObject(XrdSysLogger   *lp,
                                                     const char     *cfn,
                                                     const char     *parm,
                                                     XrdVersionInfo &myVer);


namespace {

typedef std::vector<std::pair<Access_Operation, std::string>> AccessRulesRaw;

inline uint64_t monotonic_time() {
  struct timespec tp;
#ifdef CLOCK_MONOTONIC_COARSE
  clock_gettime(CLOCK_MONOTONIC_COARSE, &tp);
#else
  clock_gettime(CLOCK_MONOTONIC, &tp);
#endif
  return tp.tv_sec + (tp.tv_nsec >= 500000000);
}

XrdAccPrivs AddPriv(Access_Operation op, XrdAccPrivs privs)
{
    int new_privs = privs;
    switch (op) {
        case AOP_Any:
            break;
        case AOP_Chmod:
            new_privs |= static_cast<int>(XrdAccPriv_Chmod);
            break;
        case AOP_Chown:
            new_privs |= static_cast<int>(XrdAccPriv_Chown);
            break;
        case AOP_Create:
            new_privs |= static_cast<int>(XrdAccPriv_Create);
            break;
        case AOP_Delete:
            new_privs |= static_cast<int>(XrdAccPriv_Delete);
            break;
        case AOP_Insert:
            new_privs |= static_cast<int>(XrdAccPriv_Insert);
            break;
        case AOP_Lock:
            new_privs |= static_cast<int>(XrdAccPriv_Lock);
            break;
        case AOP_Mkdir:
            new_privs |= static_cast<int>(XrdAccPriv_Mkdir);
            break;
        case AOP_Read:
            new_privs |= static_cast<int>(XrdAccPriv_Read);
            break;
        case AOP_Readdir:
            new_privs |= static_cast<int>(XrdAccPriv_Readdir);
            break;
        case AOP_Rename:
            new_privs |= static_cast<int>(XrdAccPriv_Rename);
            break;
        case AOP_Stat:
            new_privs |= static_cast<int>(XrdAccPriv_Lookup);
            break;
        case AOP_Update:
            new_privs |= static_cast<int>(XrdAccPriv_Update);
            break;
    };
    return static_cast<XrdAccPrivs>(new_privs);
}

bool MakeCanonical(const std::string &path, std::string &result)
{
    if (path.empty() || path[0] != '/') {return false;}

    size_t pos = 0;
    std::vector<std::string> components;
    do {
        while (path.size() > pos && path[pos] == '/') {pos++;}
        auto next_pos = path.find_first_of("/", pos);
        auto next_component = path.substr(pos, next_pos - pos);
        pos = next_pos;
        if (next_component.empty() || next_component == ".") {continue;}
        else if (next_component == "..") {
            if (!components.empty()) {
                components.pop_back();
            }
        } else {
            components.emplace_back(next_component);
        }
    } while (pos != std::string::npos);
    if (components.empty()) {
        result = "/";
        return true;
    }
    std::stringstream ss;
    for (const auto &comp : components) {
        ss << "/" << comp;
    }
    result = ss.str();
    return true;
}

void ParseCanonicalPaths(const std::string &path, std::vector<std::string> &results)
{
    size_t pos = 0;
    do {
        while (path.size() > pos && (path[pos] == ',' || path[pos] == ' ')) {pos++;}
        auto next_pos = path.find_first_of(", ", pos);
        auto next_path = path.substr(pos, next_pos - pos);
        pos = next_pos;
        if (!next_path.empty()) {
            std::string canonical_path;
            if (MakeCanonical(next_path, canonical_path)) {
                results.emplace_back(std::move(canonical_path));
            }
        }
    } while (pos != std::string::npos);
}

struct IssuerConfig
{
    IssuerConfig(const std::string &issuer_name,
                 const std::string &issuer_url,
                 const std::vector<std::string> &base_paths,
                 const std::vector<std::string> &restricted_paths,
                 bool map_subject,
                 const std::string &default_user)
        : m_map_subject(map_subject),
          m_name(issuer_name),
          m_url(issuer_url),
          m_default_user(default_user),
          m_base_paths(base_paths),
          m_restricted_paths(restricted_paths)
    {}

    const bool m_map_subject;
    const std::string m_name;
    const std::string m_url;
    const std::string m_default_user;
    const std::vector<std::string> m_base_paths;
    const std::vector<std::string> m_restricted_paths;
};

}


class XrdAccRules
{
public:
    XrdAccRules(uint64_t expiry_time, const std::string &username, const std::string &issuer) :
        m_expiry_time(expiry_time),
        m_username(username),
        m_issuer(issuer)
    {}

    ~XrdAccRules() {}

    bool apply(Access_Operation oper, std::string path) {
        for (const auto & rule : m_rules) {
            if ((oper == rule.first) && !path.compare(0, rule.second.size(), rule.second, 0, rule.second.size())) {
                return true;
            }
        }
        return false;
    }

    bool expired() const {return monotonic_time() > m_expiry_time;}

    void parse(const AccessRulesRaw &rules) {
        m_rules.reserve(rules.size());
        for (const auto &entry : rules) {
            m_rules.emplace_back(entry.first, entry.second);
        }
    }

    const std::string & get_username() const {return m_username;}
    const std::string & get_issuer() const {return m_issuer;}

private:
    AccessRulesRaw m_rules;
    uint64_t m_expiry_time{0};
    const std::string m_username;
    const std::string m_issuer;
};

class XrdAccSciTokens;

XrdAccSciTokens *accSciTokens = nullptr;

class XrdAccSciTokens : public XrdAccAuthorize, public XrdSciTokensHelper
{

    enum class AuthzBehavior {
        PASSTHROUGH,
        ALLOW,
        DENY
    };

public:
    XrdAccSciTokens(XrdSysLogger *lp, const char *parms, std::unique_ptr<XrdAccAuthorize> chain) :
        m_chain(std::move(chain)),
        m_parms(parms ? parms : ""),
        m_next_clean(monotonic_time() + m_expiry_secs),
        m_log(lp, "scitokens_")
    {
        pthread_rwlock_init(&m_config_lock, nullptr);
        m_config_lock_initialized = true;
        m_log.Say("++++++ XrdAccSciTokens: Initialized SciTokens-based authorization.");
        if (!Reconfig()) {
            throw std::runtime_error("Failed to configure SciTokens authorization.");
        }
    }

    virtual ~XrdAccSciTokens() {
        if (m_config_lock_initialized) {
            pthread_rwlock_destroy(&m_config_lock);
        }
    }

    virtual XrdAccPrivs Access(const XrdSecEntity *Entity,
                                  const char         *path,
                                  const Access_Operation oper,
                                        XrdOucEnv       *env) override
    {
        const char *authz = env ? env->Get("authz") : nullptr;
        if (authz == nullptr) {
            return OnMissing(Entity, path, oper, env);
        }
        std::shared_ptr<XrdAccRules> access_rules;
        uint64_t now = monotonic_time();
        Check(now);
        {
            std::lock_guard<std::mutex> guard(m_mutex);
            const auto iter = m_map.find(authz);
            if (iter != m_map.end() && !iter->second->expired()) {
                access_rules = iter->second;
            }
        }
        if (!access_rules) {
            try {
		uint64_t cache_expiry;
		AccessRulesRaw rules;
                std::string username;
                std::string issuer;
                if (GenerateAcls(authz, cache_expiry, rules, username, issuer)) {
                    access_rules.reset(new XrdAccRules(now + cache_expiry, username, issuer));
                    access_rules->parse(rules);
                } else {
                    return OnMissing(Entity, path, oper, env);
                }
            } catch (std::exception &exc) {
                m_log.Emsg("Access", "Error generating ACLs for authorization", exc.what());
                return OnMissing(Entity, path, oper, env);
            }
            std::lock_guard<std::mutex> guard(m_mutex);
            m_map[authz] = access_rules;
        }
        const std::string &username = access_rules->get_username();
        if (!username.empty() && !Entity->name) {
            const_cast<XrdSecEntity*>(Entity)->name = strdup(username.c_str());
        }
        const auto &issuer = access_rules->get_issuer();
        if (!issuer.empty() && !Entity->vorg) {
            const_cast<XrdSecEntity*>(Entity)->vorg = strdup(issuer.c_str());
        }
        auto result = access_rules->apply(oper, path);
        return result ? AddPriv(oper, XrdAccPriv_None) : OnMissing(Entity, path, oper, env);
    }

    virtual  Issuers IssuerList() override
    {
        /*
        Convert the m_issuers into the data structure:
        struct   ValidIssuer
        {std::string issuer_name;
         std::string issuer_url;
        };
        typedef std::vector<ValidIssuer> Issuers;
        */
        Issuers issuers;
        for (auto it: m_issuers) {
            ValidIssuer issuer_info;
            issuer_info.issuer_name = it.first;
            issuer_info.issuer_url = it.second.m_url;
            issuers.push_back(issuer_info);
        }
        return issuers;

    }

    virtual bool Validate(const char *token, std::string &emsg)
    {
        // Just check if the token is valid, no scope checking

        // Deserialize the token
        SciToken scitoken;
        char *err_msg;
        pthread_rwlock_rdlock(&m_config_lock);
        auto retval = scitoken_deserialize(token, &scitoken, &m_valid_issuers_array[0], &err_msg);
        pthread_rwlock_unlock(&m_config_lock);
        if (retval) {
            // This originally looked like a JWT so log the failure.
            m_log.Emsg("Validate", "Failed to deserialize SciToken:", err_msg);
            emsg = err_msg;
            free(err_msg);
            return false;
        }

        // Delete the scitokens
        scitoken_destroy(scitoken);

        // Deserialize checks the key, so we're good now.
        return true;
    }

    virtual int Audit(const int              accok,
                      const XrdSecEntity    *Entity,
                      const char            *path,
                      const Access_Operation oper,
                            XrdOucEnv       *Env=0) override
    {
        return 0;
    }

    virtual int         Test(const XrdAccPrivs priv,
                             const Access_Operation oper) override
    {
        return 0;
    }

    std::string GetConfigFile() {
        return m_cfg_file;
    }

    static XrdSciTokensHelper* InitViaZTN(XrdSysLogger *lp,
                                             const char   *cfn,
                                             const char   *parm,
                                             XrdAccAuthorize *accP)
    {
        try {
            std::unique_ptr<XrdAccAuthorize> chain(accP);
            accSciTokens = new XrdAccSciTokens(lp, parm, std::move(chain)); // The last arg not needed!
            return (XrdSciTokensHelper*)accSciTokens;
        } catch (std::exception &) {
            return nullptr;
        }
    }

private:
    XrdAccPrivs OnMissing(const XrdSecEntity *Entity, const char *path,
                          const Access_Operation oper, XrdOucEnv *env)
    {
        switch (m_authz_behavior) {
            case AuthzBehavior::PASSTHROUGH:
                return m_chain ? m_chain->Access(Entity, path, oper, env) : XrdAccPriv_None;
            case AuthzBehavior::ALLOW:
                return AddPriv(oper, XrdAccPriv_None);
            case AuthzBehavior::DENY:
                return XrdAccPriv_None;
        }
        // Code should be unreachable.
        return XrdAccPriv_None;
    }

    bool GenerateAcls(const std::string &authz, uint64_t &cache_expiry, AccessRulesRaw &rules, std::string &username, std::string &issuer) {
        if (strncmp(authz.c_str(), "Bearer%20", 9)) {
            return false;
        }

        // Does this look like a JWT?  If not, bail out early and
        // do not pollute the log.
        bool looks_good = true;
        int separator_count = 0;
        for (auto cur_char = authz.c_str() + 9; *cur_char; cur_char++) {
            if (*cur_char == '.') {
                separator_count++;
                if (separator_count > 2) {
                    break;
                }
            } else
            if (!(*cur_char >= 65 && *cur_char <= 90) && // uppercase letters
                !(*cur_char >= 97 && *cur_char <= 122) && // lowercase letters
                !(*cur_char >= 48 && *cur_char <= 57) && // numbers
                (*cur_char != 43) && (*cur_char != 47) && // + and /
                (*cur_char != 45) && (*cur_char != 95)) // - and _
            {
                looks_good = false;
                break;
            }
        }
        if ((separator_count != 2) || (!looks_good)) {
            return false;
        }

        char *err_msg;
        SciToken token = nullptr;
        pthread_rwlock_rdlock(&m_config_lock);
        auto retval = scitoken_deserialize(authz.c_str() + 9, &token, &m_valid_issuers_array[0], &err_msg);
        pthread_rwlock_unlock(&m_config_lock);
        if (retval) {
            // This originally looked like a JWT so log the failure.
            m_log.Emsg("GenerateAcls", "Failed to deserialize SciToken:", err_msg);
            free(err_msg);
            return false;
        }

        long long expiry;
        if (scitoken_get_expiration(token, &expiry, &err_msg)) {
            m_log.Emsg("GenerateAcls", "Unable to determine token expiration:", err_msg);
            free(err_msg);
            scitoken_destroy(token);
            return false;
        }
        if (expiry > 0) {
            expiry = std::max(static_cast<int64_t>(monotonic_time() - expiry),
                static_cast<int64_t>(60));
        } else {
            expiry = 60;
        }

        char *value = nullptr;
        if (scitoken_get_claim_string(token, "iss", &value, &err_msg)) {
            m_log.Emsg("GenerateAcls", "Failed to get issuer:", err_msg);
            scitoken_destroy(token);
            free(err_msg);
            return false;
        }
        std::string token_issuer(value);
        free(value);

        pthread_rwlock_rdlock(&m_config_lock);
        auto enf = enforcer_create(token_issuer.c_str(), &m_audiences_array[0], &err_msg);
        pthread_rwlock_unlock(&m_config_lock);
        if (!enf) {
            m_log.Emsg("GenerateAcls", "Failed to create an enforcer:", err_msg);
            scitoken_destroy(token);
            free(err_msg);
            return false;
        }

        Acl *acls = nullptr;
        if (enforcer_generate_acls(enf, token, &acls, &err_msg)) {
            scitoken_destroy(token);
            enforcer_destroy(enf);
            m_log.Emsg("GenerateAcls", "ACL generation from SciToken failed:", err_msg);
            free(err_msg);
            return false;
        }
        enforcer_destroy(enf);

        pthread_rwlock_rdlock(&m_config_lock);
        auto iter = m_issuers.find(token_issuer);
        if (iter == m_issuers.end()) {
            pthread_rwlock_unlock(&m_config_lock);
            m_log.Emsg("GenerateAcls", "Authorized issuer without a config.");
            scitoken_destroy(token);
            return false;
        }
        const auto &config = iter->second;
        std::string token_username;
        if (config.m_map_subject) {
            value = nullptr;
            if (scitoken_get_claim_string(token, "sub", &value, &err_msg)) {
                pthread_rwlock_unlock(&m_config_lock);
                m_log.Emsg("GenerateAcls", "Failed to get token subject:", err_msg);
                free(err_msg);
                scitoken_destroy(token);
                return false;
            }
            token_username = std::string(value);
            free(value);
        } else {
            token_username = config.m_default_user;
        }

        AccessRulesRaw xrd_rules;
        int idx = 0;
        while (acls[idx].resource && acls[idx++].authz) {
            const auto &acl_path = acls[idx-1].resource;
            const auto &acl_authz = acls[idx-1].authz;
            if (!config.m_restricted_paths.empty()) {
                bool found_path = false;
                for (const auto &restricted_path : config.m_restricted_paths) {
                    if (!strncmp(acl_path, restricted_path.c_str(), restricted_path.size())) {
                        found_path = true;
                        break;
                    }
                }
                if (!found_path) {continue;}
            }
            for (const auto &base_path : config.m_base_paths) {
                if (!acl_path[0] || acl_path[0] != '/') {continue;}
                std::string path;
                MakeCanonical(base_path + acl_path, path);
                if (!strcmp(acl_authz, "read")) {
                    xrd_rules.emplace_back(AOP_Read, path);
                    xrd_rules.emplace_back(AOP_Stat, path);
                } else if (!strcmp(acl_authz, "write")) {
                    xrd_rules.emplace_back(AOP_Update, path);
                    xrd_rules.emplace_back(AOP_Create, path);
                    xrd_rules.emplace_back(AOP_Mkdir, path);
                    xrd_rules.emplace_back(AOP_Chmod, path);
                    xrd_rules.emplace_back(AOP_Delete, path);
                    xrd_rules.emplace_back(AOP_Insert, path);
                    xrd_rules.emplace_back(AOP_Rename, path);
                    xrd_rules.emplace_back(AOP_Update, path);
                }
            }
        }

        pthread_rwlock_unlock(&m_config_lock);

        cache_expiry = expiry;
        rules = std::move(xrd_rules);
        username = std::move(token_username);
        issuer = std::move(token_issuer);

        return true;
    }

    bool Reconfig()
    {
        errno = 0;
        m_cfg_file = "/etc/xrootd/scitokens.cfg";
        if (!m_parms.empty()) {
            size_t pos = 0;
            std::vector<std::string> arg_list;
            do {
                while ((m_parms.size() > pos) && (m_parms[pos] == ' ')) {pos++;}
                auto next_pos = m_parms.find_first_of(", ", pos);
                auto next_arg = m_parms.substr(pos, next_pos - pos);
                pos = next_pos;
                if (!next_arg.empty()) {
                    arg_list.emplace_back(std::move(next_arg));
                }
            } while (pos != std::string::npos);

            for (const auto &arg : arg_list) {
                if (strncmp(arg.c_str(), "config=", 7)) {
                    m_log.Emsg("Reconfig", "Ignoring unknown configuration argument:", arg.c_str());
                    continue;
                }
                m_cfg_file = std::string(arg.c_str() + 7);
            }
        }
        m_log.Emsg("Reconfig", "Parsing configuration file:", m_cfg_file.c_str());

        INIReader reader(m_cfg_file);
        if (reader.ParseError() < 0) {
            std::stringstream ss;
            ss << "Error opening config file (" << m_cfg_file << "): " << strerror(errno);
            m_log.Emsg("Reconfig", ss.str().c_str());
            return false;
        } else if (reader.ParseError()) {
            std::stringstream ss;
            ss << "Parse error on line " << reader.ParseError() << " of file " << m_cfg_file;
            m_log.Emsg("Reconfig", ss.str().c_str());
            return false;
        }
        std::vector<std::string> audiences;
        std::unordered_map<std::string, IssuerConfig> issuers;
        for (const auto &section : reader.Sections()) {
            std::string section_lower;
            std::transform(section.begin(), section.end(), std::back_inserter(section_lower),
                [](unsigned char c){ return std::tolower(c); });

            if (section_lower.substr(0, 6) == "global") {
                auto audience = reader.Get(section, "audience", "");
                if (!audience.empty()) {
                    size_t pos = 0;
                    do {
                        while (audience.size() > pos && (audience[pos] == ',' || audience[pos] == ' ')) {pos++;}
                        auto next_pos = audience.find_first_of(", ", pos);
                        auto next_aud = audience.substr(pos, next_pos - pos);
                        pos = next_pos;
                        if (!next_aud.empty()) {
                            audiences.push_back(next_aud);
                        }
                    } while (pos != std::string::npos);
                }
                audience = reader.Get(section, "audience_json", "");
                if (!audience.empty()) {
                    picojson::value json_obj;
                    auto err = picojson::parse(json_obj, audience);
                    if (!err.empty()) {
                        m_log.Emsg("Reconfig", "Unable to parse audience_json:", err.c_str());
                        return false;
                    }
                    if (!json_obj.is<picojson::value::array>()) {
                        m_log.Emsg("Reconfig", "audience_json must be a list of strings; not a list.");
                        return false;
                    }
                    for (const auto &val : json_obj.get<picojson::value::array>()) {
                        if (!val.is<std::string>()) {
                            m_log.Emsg("Reconfig", "audience must be a list of strings; value is not a string.");
                            return false;
                        }
                        audiences.push_back(val.get<std::string>());
                    }
                }
                auto onmissing = reader.Get(section, "onmissing", "");
                if (onmissing == "passthrough") {
                    m_authz_behavior = AuthzBehavior::PASSTHROUGH;
                } else if (onmissing == "allow") {
                    m_authz_behavior = AuthzBehavior::ALLOW;
                } else if (onmissing == "deny") {
                    m_authz_behavior = AuthzBehavior::DENY;
                } else if (!onmissing.empty()) {
                    m_log.Emsg("Reconfig", "Unknown value for onmissing key:", onmissing.c_str());
                    return false;
                }
            }

            if (section_lower.substr(0, 7) != "issuer ") {continue;}

            auto issuer = reader.Get(section, "issuer", "");
            if (issuer.empty()) {
                m_log.Emsg("Reconfig", "Ignoring section because 'issuer' attribute is not set:",
                     section.c_str());
                continue;
            }

            auto base_path = reader.Get(section, "base_path", "");
            if (base_path.empty()) {
                m_log.Emsg("Reconfig", "Ignoring section because 'base_path' attribute is not set:",
                     section.c_str());
                continue;
            }

            size_t pos = 7;
            while (section.size() > pos && std::isspace(section[pos])) {pos++;}

            auto name = section.substr(pos);
            if (name.empty()) {
                m_log.Emsg("Reconfig", "Invalid section name:", section.c_str());
                continue;
            }

            std::vector<std::string> base_paths;
            ParseCanonicalPaths(base_path, base_paths);

            auto restricted_path = reader.Get(section, "restricted_path", "");
            std::vector<std::string> restricted_paths;
            if (!restricted_path.empty()) {
                ParseCanonicalPaths(restricted_path, restricted_paths);
            }

            auto default_user = reader.Get(section, "default_user", "");
            auto map_subject = reader.GetBoolean(section, "map_subject", false);

            issuers.emplace(std::piecewise_construct,
                            std::forward_as_tuple(issuer),
                            std::forward_as_tuple(name, issuer, base_paths, restricted_paths,
                                                  map_subject, default_user));
        }

        if (issuers.empty()) {
            m_log.Emsg("Reconfig", "No issuers configured.");
            return false;
        }

        pthread_rwlock_wrlock(&m_config_lock);
        try {
            m_audiences = std::move(audiences);
            size_t idx = 0;
            m_audiences_array.resize(m_audiences.size() + 1);
            for (const auto &audience : m_audiences) {
                m_audiences_array[idx++] = audience.c_str();
            }
            m_audiences_array[idx] = nullptr;

            m_issuers = std::move(issuers);
            m_valid_issuers_array.resize(m_issuers.size() + 1);
            idx = 0;
            for (const auto &issuer : m_issuers) {
                m_valid_issuers_array[idx++] = issuer.first.c_str();
            }
            m_valid_issuers_array[idx] = nullptr;
        } catch (...) {
            pthread_rwlock_unlock(&m_config_lock);
            return false;
        }
        pthread_rwlock_unlock(&m_config_lock);
        return true;
    }

    void Check(uint64_t now)
    {
        if (now <= m_next_clean) {return;}
        std::lock_guard<std::mutex> guard(m_mutex);

        for (auto iter = m_map.begin(); iter != m_map.end(); iter++) {
            if (iter->second->expired()) {
                m_map.erase(iter);
            }
        }
        Reconfig();

        m_next_clean = monotonic_time() + m_expiry_secs;
    }

    bool m_config_lock_initialized{false};
    std::mutex m_mutex;
    pthread_rwlock_t m_config_lock;
    std::vector<std::string> m_audiences;
    std::vector<const char *> m_audiences_array;
    std::map<std::string, std::shared_ptr<XrdAccRules>> m_map;
    std::unique_ptr<XrdAccAuthorize> m_chain;
    const std::string m_parms;
    std::vector<const char*> m_valid_issuers_array;
    std::unordered_map<std::string, IssuerConfig> m_issuers;
    uint64_t m_next_clean{0};
    XrdSysError m_log;
    AuthzBehavior m_authz_behavior{AuthzBehavior::PASSTHROUGH};
    std::string m_cfg_file;

    static constexpr uint64_t m_expiry_secs = 60;
};

std::string      cfgSciTokens;

extern "C" {

XrdAccAuthorize *XrdAccAuthorizeObjectAdd(XrdSysLogger *lp,
                                          const char   *cfn,
                                          const char   *parm,
                                       XrdAccAuthorize *accP)
{
    // Record the parent authorization plugin. There is no need to use
    // unique_ptr as all of this happens once in the main and only thread.
    //

    // Create a logging platform to send error messages
    XrdSysError xrootdLog(lp, "scitokens_");
    // If we have been initialized by via InitViaZTN() then all we need to check
    // is that the config file passed here is the same one passed via the ZTN.
    // If it isn't, issue a nasty message and return a nil pointer.
    //
    if (accSciTokens)  // Already initialzed?
    {
        // Verify sameness of config file
        if (accSciTokens->GetConfigFile() == cfn) {
            return accSciTokens;
        } else {
            xrootdLog.Emsg("XrdAccAuthorizeObjectAdd", "SciTokens configuration is different now from the scitokens configuration when initialized");
            return nullptr;
        }
    }

    // First time through, get a new SciTokens authorizer. We simply reuse the
    // InitViaZTN() method as that is all we need.
    //
    accSciTokens = (XrdAccSciTokens*)XrdAccSciTokens::InitViaZTN(lp, cfn, parm, accP);
    return (accSciTokens ? accSciTokens : nullptr);
}



}
