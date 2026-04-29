#
# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#

Name:           libsgx-ra-uefi
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) Software Guard Extensions Registration Agent UEFI Library
Group:          Development/Libraries

License:        BSD License
URL:            https://github.com/intel/SGXDataCenterAttestationPrimitives
Source0:        %{name}-%{version}.tar.gz

%description
Intel(R) Software Guard Extensions Registration Agent UEFI Library

%package devel
Summary:        Intel(R) Software Guard Extensions Registration Agent UEFI Library for Developers
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release}

%description devel
Intel(R) Software Guard Extensions Registration Agent UEFI Library for Developers

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
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

%files -f %{_specdir}/list-%{name}

%files devel -f %{_specdir}/list-%{name}-devel

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
* Mon Feb 10 2020 SGX Team
- Initial Release
