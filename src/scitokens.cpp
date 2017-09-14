
#include "XrdAcc/XrdAccAuthorize.hh"
#include "XrdSys/XrdSysLogger.hh"
#include "XrdVersion.hh"

#include <boost/python.hpp>

#include <map>
#include <mutex>
#include <string>
#include <vector>

XrdVERSIONINFO(XrdAccAuthorizeObject, XrdAccSciTokens);

class XrdAccRules
{
public:
    XrdAccRules() {}

    ~XrdAccRules() {}

    bool apply(Access_Operation, std::string path) {return false;}

private:
    std::vector<std::pair<Access_Operation, std::string>> m_rules;
};

class XrdAccSciTokens : XrdAccAuthorize
{
public:
    XrdAccSciTokens() :
        module(boost::python::import("scitokens.xrootd"))
    {}

    virtual ~XrdAccSciTokens() {}

    virtual XrdAccPrivs Access(const XrdSecEntity *Entity,
                                  const char         *path,
                                  const Access_Operation oper,
                                        XrdOucEnv       *env)
    {
        return XrdAccPriv_None;
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
    std::mutex m_mutex;
    std::map<std::string, std::pair<time_t, XrdAccRules>> m_map;
    boost::python::object module;
};

extern "C" {

XrdAccAuthorize *XrdAccAuthorizeObject(XrdSysLogger *lp,
                                       const char   *cfn,
                                       const char   *parm)
{
    return nullptr;
}

}
