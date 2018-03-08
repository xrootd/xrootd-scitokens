
#include "XrdAcc/XrdAccAuthorize.hh"
#include "XrdOuc/XrdOucEnv.hh"
#include "XrdSec/XrdSecEntity.hh"
#include "XrdSys/XrdSysLogger.hh"
#include "XrdVersion.hh"

#include <boost/python.hpp>

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <dlfcn.h>

XrdVERSIONINFO(XrdAccAuthorizeObject, XrdAccSciTokens);

// The status-quo to retrieve the default object is to copy/paste the
// linker definition and invoke directly.
static XrdVERSIONINFODEF(compiledVer, XrdAccTest, XrdVNUMBER, XrdVERSION);
extern XrdAccAuthorize *XrdAccDefaultAuthorizeObject(XrdSysLogger   *lp,
                                                     const char     *cfn,
                                                     const char     *parm,
                                                     XrdVersionInfo &myVer);


static std::string
handle_pyerror()
{
    PyObject *exc,*val,*tb;
    boost::python::object formatted_list, formatted;
    PyErr_Fetch(&exc,&val,&tb);
    boost::python::handle<> hexc(exc), hval(boost::python::allow_null(val)), htb(boost::python::allow_null(tb));
    boost::python::object traceback(boost::python::import("traceback"));
    boost::python::object format_exception(traceback.attr("format_exception"));
    formatted_list = format_exception(hexc,hval,htb);
    formatted = boost::python::str("\n").join(formatted_list);
    return boost::python::extract<std::string>(formatted);
}


static inline uint64_t monotonic_time() {
  struct timespec tp;
#ifdef CLOCK_MONOTONIC_COARSE
  clock_gettime(CLOCK_MONOTONIC_COARSE, &tp);
#else
  clock_gettime(CLOCK_MONOTONIC, &tp);
#endif
  return tp.tv_sec + (tp.tv_nsec >= 500000000);
}


static XrdAccPrivs AddPriv(Access_Operation op, XrdAccPrivs privs)
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

class XrdAccRules
{
public:
    XrdAccRules(uint64_t expiry_time, const std::string &username) :
        m_expiry_time(expiry_time),
        m_username(username)
    {}

    ~XrdAccRules() {}

    XrdAccPrivs apply(Access_Operation, std::string path) {
        XrdAccPrivs privs = XrdAccPriv_None;
        for (const auto & rule : m_rules) {
            if (!path.compare(0, rule.second.size(), rule.second, 0, rule.second.size())) {
                privs = AddPriv(rule.first, privs);
            }
        }
        return privs;
    }

    bool expired() const {return monotonic_time() > m_expiry_time;}

    void parse(boost::python::list results) {
        int cache_len = boost::python::len(results);
        for (int idx=0; idx<cache_len; idx++) {
            boost::python::object entry = results[idx];
            Access_Operation aop = boost::python::extract<Access_Operation>(entry[0]);
            std::string path = boost::python::extract<std::string>(entry[1]);
            m_rules.emplace_back(aop, path);
        }
    }

    const std::string & get_username() const {return m_username;}

private:
    std::vector<std::pair<Access_Operation, std::string>> m_rules;
    uint64_t m_expiry_time{0};
    const std::string m_username;
};

class XrdAccSciTokens : public XrdAccAuthorize
{
public:
    XrdAccSciTokens(XrdSysLogger *lp, const char *parms, std::unique_ptr<XrdAccAuthorize> chain) :
        m_module(boost::python::import("scitokens_xrootd")),
        m_chain(std::move(chain)),
        m_next_clean(monotonic_time() + m_expiry_secs),
        m_log(lp, "scitokens_")
    {
        m_log.Say("++++++ XrdAccSciTokens: Initialized SciTokens-based authorization.");
        if (parms) {
            m_log.Say("Initializing python module with params ", parms);
            m_module.attr("init")(parms);
        } else {
            m_log.Say("Initializing python module with no configuration parameters");
            m_module.attr("init")();
        }
        m_log.Say("Finished python module initialization.");
    }

    virtual ~XrdAccSciTokens() {}

    virtual XrdAccPrivs Access(const XrdSecEntity *Entity,
                                  const char         *path,
                                  const Access_Operation oper,
                                        XrdOucEnv       *env)
    {
        const char *authz = env ? env->Get("authz") : nullptr;
        if (authz == nullptr) {
            return m_chain ? m_chain->Access(Entity, path, oper, env) : XrdAccPriv_None;
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
            std::lock_guard<std::mutex> guard(m_mutex);
            try {
                boost::python::object retval = m_module.attr("generate_acls")(authz);
                boost::python::list cache = boost::python::list(retval[1]);
                std::string username = boost::python::extract<std::string>(retval[2]);
                //m_log.Emsg("Access", "SciTokens library returned suggested username", username.c_str());
                uint64_t cache_expiry = boost::python::extract<uint64_t>(retval[0]);
                access_rules.reset(new XrdAccRules(now + cache_expiry, username));
                access_rules->parse(cache);
            } catch (boost::python::error_already_set) {
                m_log.Emsg("Access", "Error generating ACLs for authorization", handle_pyerror().c_str());
                return m_chain ? m_chain->Access(Entity, path, oper, env) : XrdAccPriv_None;
            }
            m_map[authz] = access_rules;
        }
        const std::string &username = access_rules->get_username();
        if (!username.empty() && !Entity->name) {
            const_cast<XrdSecEntity*>(Entity)->name = strdup(username.c_str());
        }
        XrdAccPrivs result = access_rules->apply(oper, path);
        return ((result == XrdAccPriv_None) && m_chain) ? m_chain->Access(Entity, path, oper, env) : result;
    }

    virtual int Audit(const int              accok,
                      const XrdSecEntity    *Entity,
                      const char            *path,
                      const Access_Operation oper,
                            XrdOucEnv       *Env=0)
    {
        return 0;
    }

    virtual int         Test(const XrdAccPrivs priv,
                             const Access_Operation oper)
    {
        return 0;
    }

private:

    void Check(uint64_t now)
    {
        if (now <= m_next_clean) {return;}

        for (auto iter = m_map.begin(); iter != m_map.end(); iter++) {
            if (iter->second->expired()) {
                m_map.erase(iter);
            }
        }
    }

    std::mutex m_mutex;
    std::map<std::string, std::shared_ptr<XrdAccRules>> m_map;
    boost::python::object m_module;
    std::unique_ptr<XrdAccAuthorize> m_chain;
    uint64_t m_next_clean{0};
    XrdSysError m_log;

    static constexpr uint64_t m_expiry_secs = 60;
};

extern "C" {

XrdAccAuthorize *XrdAccAuthorizeObject(XrdSysLogger *lp,
                                       const char   *cfn,
                                       const char   *parm)
{
    // First, try to initialize the embedded python.
    if (!Py_IsInitialized())
    {
        char pname[] = "xrootd";
        Py_SetProgramName(pname);
        Py_InitializeEx(0);
    }
    // We need to reload the current shared library:
    //   - RTLD_GLOBAL instructs the loader to put everything into the global symbol table.  Python
    //     requires this for several modules.
    //   - RTLD_NOLOAD instructs the loader to actually reload instead of doing an initial load.
    //   - RTLD_NODELETE instructs the loader to not unload this library -- we need python kept in
    //     memory!
    void *handle = dlopen("libXrdAccSciTokens-4.so", RTLD_GLOBAL|RTLD_NODELETE|RTLD_NOLOAD|RTLD_LAZY);
    if (handle == nullptr) {
        XrdSysError eDest(lp, "scitokens_");
        eDest.Emsg("XrdAccSciTokens", "Failed to reload python libraries:", dlerror());
        return nullptr;
    }
    dlclose(handle);  // Per use of RTLD_NODELETE|RTLD_NOLOAD, does not actually unload this library!

    std::unique_ptr<XrdAccAuthorize> def_authz(XrdAccDefaultAuthorizeObject(lp, cfn, parm, compiledVer));
    XrdAccSciTokens *authz{nullptr};
    try {
        authz = new XrdAccSciTokens(lp, parm, std::move(def_authz));
    } catch (boost::python::error_already_set) {
        XrdSysError eDest(lp, "scitokens_");
        eDest.Emsg("XrdAccSciTokens", "Python failure initializing module:", handle_pyerror().c_str());
    }
    return authz;
}

}
