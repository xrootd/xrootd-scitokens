#!/bin/bash -xe

OS_VERSION=$1

# Clean the yum cache
yum -y clean all
yum -y clean expire-cache

# First, install all the needed packages.
rpm -Uvh https://dl.fedoraproject.org/pub/epel/epel-release-latest-${OS_VERSION}.noarch.rpm

yum -y install yum-plugin-priorities rpm-build gcc gcc-c++ boost-devel boost-python cmake git tar gzip make autotools python-devel

rpm -Uvh https://repo.opensciencegrid.org/osg/3.4/osg-3.4-el${OS_VERSION}-release-latest.rpm

# Prepare the RPM environment
mkdir -p /tmp/rpmbuild/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cp xrootd-scitokens/rpm/xrootd-scitokens.spec /tmp/rpmbuild/SPECS

package_version=`grep Version xrootd-scitokens/rpm/xrootd-scitokens.spec | awk '{print $2}'`
pushd xrootd-scitokens
git archive --format=tar --prefix=xrootd-scitokens-${package_version}/ HEAD | \
    gzip > /tmp/rpmbuild/SOURCES/xrootd-scitokens-${package_version}.tar.gz
popd

# Build the RPM
rpmbuild --define '_topdir /tmp/rpmbuild' -ba /tmp/rpmbuild/SPECS/xrootd-scitokens

# After building the RPM, try to install it
# Fix the lock file error on EL7.  /var/lock is a symlink to /var/run/lock
mkdir -p /var/run/lock

RPM_LOCATION=/tmp/rpmbuild/RPMS/x86_64

yum localinstall -y $RPM_LOCATION/xrootd-scitokens-${package_version}*

