#
# Copyright(c) 2011-2025 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

%define _license_file COPYING

Name:           libsgx-dcap-default-qpl
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) Software Guard Extensions Default Quote Provider Library
Group:          Development/Libraries

License:        BSD License
URL:            https://github.com/intel/SGXDataCenterAttestationPrimitives
Source0:        %{name}-%{version}.tar.gz
%if 0%{?suse_version}
Requires: libcurl4
%else
Requires: libcurl
%endif

%description
Intel(R) Software Guard Extensions Default Quote Provider Library

%package devel
Summary:        Intel(R) Software Guard Extensions Default Quote Provider Library for Developers
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description devel
Intel(R) Software Guard Extensions Default Quote Provider Library for Developers

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
install -d %{?buildroot}/%{name}%{_docdir}/%{name}
find %{?_sourcedir}/package/licenses/ -type f -print0 | xargs -0 -n1 cat >> %{?buildroot}/%{name}%{_docdir}/%{name}/%{_license_file}
rm -f %{_specdir}/list-%{name}
for f in $(find %{?buildroot}/%{name} -type f -o -type l); do
    echo $f | sed -e "s#%{?buildroot}/%{name}##" >> %{_specdir}/list-%{name}
done
cp -r %{?buildroot}/%{name}/* %{?buildroot}/
rm -fr %{?buildroot}/%{name}
rm -f %{_specdir}/list-%{name}-devel
for f in $(find %{?buildroot}/%{name}-dev -type f -o -type l); do
    echo $f | sed -e "s#%{?buildroot}/%{name}-dev##" >> %{_specdir}/list-%{name}-devel
done
cp -r %{?buildroot}/%{name}-dev/* %{?buildroot}/
rm -fr %{?buildroot}/%{name}-dev
sed -i 's#^/etc/sgx_default_qcnl.conf#%config &#' %{_specdir}/list-%{name}

%files -f %{_specdir}/list-%{name}

%files devel -f %{_specdir}/list-%{name}-devel

%debug_package

%changelog
* Mon Mar 09 2020 SGX Team
- Initial Release
