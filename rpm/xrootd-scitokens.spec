Name: xrootd-scitokens
Version: 1.2.0
Release: 2%{?dist}
Summary: SciTokens authentication plugin for XRootD
License: Apache 2.0
URL: https://github.com/scitokens/xrootd-scitokens

# Generated from:
# git archive v%{version} --prefix=xrootd-scitokens-%{version}/ | gzip -7 > ~/rpmbuild/SOURCES/xrootd-scitokens-%{version}.tar.gz
Source0: %{name}-%{version}.tar.gz

# Only on EL 7 and newer:
BuildRequires: gcc-c++ >= 4.8

BuildRequires: gcc-c++
BuildRequires: cmake
BuildRequires: xrootd-server-devel
BuildRequires: scitokens-cpp-devel

%description
SciTokens authentication plugin for XRootD

%prep
%setup -q

%build
mkdir build
cd build
%cmake ..
make 

%install
pushd build
rm -rf $RPM_BUILD_ROOT
echo $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
popd

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%{_libdir}/libXrdAccSciTokens-*.so

%defattr(-,root,root,-)

%changelog
* Wed Jun 10 2020 Diego Davila <didavila@ucsd.edu> - 1.2.0-2
- Adding XrootD major version to the shared file name
- building against XrootD-4.12.2 (software-4093)

* Tue Mar 10 2020 Derek Weitzel <dweitzel@cse.unl.edu> - 1.2.0-1
- Add issuer for latter mapping decisions by issuer
- Correct access control when allowing only reads

* Thu Jan 16 2020 Derek Weitzel <dweitzel@cse.unl.edu> - 1.1.0-1
- Allow passthrough of the scitokens to other authz

* Thu May 16 2019 Derek Weitzel <dweitzel@cse.unl.edu> - 1.0.0-1
- Switch from the SciTokens Python API to the C API

* Tue Oct 23 2018 Derek Weitzel <dweitzel@cse.unl.edu> - 0.6.0-1
- Add support for audiences and multiple audience support

* Thu Mar 08 2018 Brian Bockelman <bbockelm@cse.unl.edu> - 0.5.0-1
- Add support for multiple base paths of an issuer.
- Add concept of restricting authorized paths within an issuer's namespace.
- Fix potential segfault when a user environment isnt available.

* Tue Feb 06 2018 Derek Weitzel <dweitzel@cse.unl.edu> - 0.4.0-1
- Update to v0.4.0

* Mon Nov 06 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 0.3.1-1
- Fix issue with translating write authz.

* Wed Sep 20 2017 Brian Bockelman <bbockelm@cse.unl.edu> - 0.2.0-1
- Remove urltools dependency.

* Wed Sep 20 2017 Lincoln Bryant <lincolnb@uchicago.edu> - 0.1.0-1
- Initial package
