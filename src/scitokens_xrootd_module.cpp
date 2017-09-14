
#include "XrdAcc/XrdAccAuthorize.hh"

#include <boost/python.hpp>

BOOST_PYTHON_MODULE(_scitokens_xrootd)
{
    using namespace boost::python;

    boost::python::enum_<Access_Operation>("AccessOperation")
        .value("Any", Access_Operation::AOP_Any)
        .value("Chmod", Access_Operation::AOP_Chmod)
        .value("Chown", Access_Operation::AOP_Chown)
        .value("Create", Access_Operation::AOP_Create)
        .value("Delete", Access_Operation::AOP_Delete)
        .value("Insert", Access_Operation::AOP_Insert)
        .value("Lock", Access_Operation::AOP_Lock)
        .value("Mkdir", Access_Operation::AOP_Mkdir)
        .value("Read", Access_Operation::AOP_Read)
        .value("Readdir", Access_Operation::AOP_Readdir)
        .value("Stat", Access_Operation::AOP_Stat)
        .value("Update", Access_Operation::AOP_Update)
        ;


}
