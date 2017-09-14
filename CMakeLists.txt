
cmake_minimum_required( VERSION 3.1 )
project( xrootd-scitokens )

set( CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake )

find_package( Boost REQUIRED COMPONENTS python )
find_package( Xrootd REQUIRED )
find_package( PythonLibs REQUIRED )
find_package( PythonInterp REQUIRED )

set( CMAKE_CXX_STANDARD 11)
if( CMAKE_COMPILER_IS_GNUCXX )
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Werror" )
endif()
SET( CMAKE_SHARED_LINKER_FLAGS "-Wl,--no-undefined")
SET( CMAKE_MODULE_LINKER_FLAGS "-Wl,--no-undefined")

include_directories(${PYTHON_INCLUDE_DIRS} ${BOOST_INCLUDE_DIRS} ${XROOTD_INCLUDES})
add_library(_scitokens_xrootd SHARED src/scitokens_xrootd_module.cpp)
target_link_libraries(_scitokens_xrootd ${Boost_PYTHON_LIBRARY} ${PYTHON_LIBRARIES})
set_target_properties(_scitokens_xrootd PROPERTIES PREFIX "" OUTPUT_NAME _scitokens_xrootd SUFFIX ".so")

add_library(XrdAccSciTokens SHARED src/scitokens.cpp)
target_link_libraries(XrdAccSciTokens ${Boost_PYTHON_LIBRARY} ${PYTHON_LIBRARIES})
set_target_properties(XrdAccSciTokens PROPERTIES SUFFIX ".so")

SET(LIB_INSTALL_DIR "${CMAKE_INSTALL_PREFIX}/lib" CACHE PATH "Install path for libraries")

install(
  TARGETS _scitokens_xrootd
  LIBRARY DESTINATION ${LIB_INSTALL_DIR}/python${PYTHON_VERSION_MAJOR}.${PYTHON_VERSION_MINOR}/site-packages/ )

install(
  TARGETS XrdAccSciTokens
  LIBRARY DESTINATION ${LIB_INSTALL_DIR})
