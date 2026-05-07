#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

%define _license_file COPYING

Name:           libsgx-qe3-logic
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) Software Guard Extensions QE3 logic
Group:          Development/Libraries
Requires:       libsgx-urts >= 2.30 libsgx-ae-qe3 >= %{version}-%{release} libsgx-ae-id-enclave >= %{version}-%{release}

License:        BSD License
URL:            https://github.com/intel/SGXDataCenterAttestationPrimitives
Source0:        %{name}-%{version}.tar.gz

%description
Intel(R) Software Guard Extensions QE3 logic

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
install -d %{?buildroot}%{_docdir}/%{name}
find %{?_sourcedir}/package/licenses/ -type f -print0 | xargs -0 -n1 cat >> %{?buildroot}%{_docdir}/%{name}/%{_license_file}
rm -f %{_specdir}/list-%{name}
for f in $(find %{?buildroot} -type f -o -type l); do
    echo $f | sed -e "s#%{?buildroot}##" >> %{_specdir}/list-%{name}
done

%files -f %{_specdir}/list-%{name}

# Detect whether rpmbuild has modern auto-debuginfo support (rpm >= 4.14).
# We use this to keep one spec compatible across old/new RPM and only enable
# legacy debug_package handling when auto-debuginfo is not available.
%global __auto_debuginfo %{lua:
  local v = rpm.expand("%{rpmversion}")
  local maj, min = v:match("^(%d+)%.(%d+)")
  maj, min = tonumber(maj), tonumber(min)
  -- Unparseable version: assume modern RPM, skip legacy debug_package
  if not (maj and min) then print("1")
  elseif maj > 4 or (maj == 4 and min >= 14) then print("1")
  else print("0")
  end
}

%if 0%{?__auto_debuginfo} == 0
%debug_package
%endif

%changelog
* Tue Jan 21 2020 SGX Team
- Initial Release
