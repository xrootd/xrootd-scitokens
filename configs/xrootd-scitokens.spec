Name: xrootd-scitokens
Version: 0.1.0
Release: 1%{?dist}
Summary: SciTokens authentication plugin for XRootD
License: Apache 2.0
URL: https://github.com/scitokens/xrootd-scitokens

# cd ~/rpmbuild/SOURCES
# git clone --depth=1 https://github.com/scitokens/xrootd-scitokens
# rm -rf xrootd-scitokens/.git
# rm -f xrootd-scitokens/.gitignore
# tar -cvzf xrootd-scitokens-0.1.0.tar.gz xrootd-scitokens
Source0: %{name}-%{version}.tar.gz

BuildRequires: gcc-c++, cmake, python2-scitokens, boost-devel, boost-python, python-devel, xrootd-server-devel

%description
SciTokens authentication plugin for XRootD

%prep
%setup -c -n %{name}-%{version}.tar.gz 

%build
cd %{name}
mkdir build
cd build
%cmake ..
make 

%install
cd %{name}
cd build
rm -rf $RPM_BUILD_ROOT
echo $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
cd ..

%clean
rm -rf $RPM_BUILD_ROOT

%post
/sbin/ldconfig

%postun
/sbin/ldconfig

%files
%{_libdir}/libXrdAccSciTokens-4.so
%{_libdir}/python2.7/site-packages/_scitokens_xrootd.so
%{_libdir}/python2.7/site-packages/scitokens_xrootd.py*

%defattr(-,root,root,-)

%changelog
* Wed Sep 20 2017 Lincoln Bryant <lincolnb@uchicago.edu> - 0.1.0-1
- Initial package
