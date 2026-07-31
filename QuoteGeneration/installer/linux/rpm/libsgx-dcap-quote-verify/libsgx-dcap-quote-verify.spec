#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

%define _license_file COPYING

Name:           libsgx-dcap-quote-verify
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) Software Guard Extensions Data Center Attestation Primitives
Group:          Development/Libraries
Recommends:     libsgx-ae-qve >= %{version}-%{release} libsgx-urts >= 2.30

License:        BSD License
URL:            https://github.com/intel/confidential-computing.tee.dcap
Source0:        %{name}-%{version}.tar.gz

%description
Intel(R) Software Guard Extensions Data Center Attestation Primitives

%package devel
Summary:        Intel(R) Software Guard Extensions Data Center Attestation Primitives for Developers
Group:          Development/Libraries
Requires:       %{name} = %{version}-%{release} libsgx-headers >= 2.30

%description devel
Intel(R) Software Guard Extensions Data Center Attestation Primitives for Developers

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
* @date@ Intel Confidential Computing Team <confidential.computing@intel.com> - @version@-1
- Release v1.27
  See https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.27 for full release notes.

- Key changes:
  1. sgx_ql_qv_supplemental_t extended to supplemental data minor
     version 5: three new fields appended (tcb_date_current, tcb_status_current,
     sa_list_current). Callers that allocate this struct by sizeof() compiled
     against older headers will receive SGX_QL_ERROR_QVL_QVE_MISMATCH (when using
     QvE) due to a supplemental data size mismatch. Recompile against the updated headers.

* Thu Apr 30 2026 Intel Confidential Computing Team <confidential.computing@intel.com> - 1.26.100.1-1
- Release v1.26
  See https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.26 for full release notes.

- ['-devel' package changes]
  1. MOVED 'sgx_qve_header.h' file from this package to 'libsgx-headers>=2.29'
  2. CHANGED `sgx_dcap_qal.h` to define QAL-side APIs only (removed type definitions).
     Common types were extracted to 'sgx_dcap_qal_types.h' (new, provided by 'libsgx-headers>=2.29')

* Wed Mar 4 2026 Intel Confidential Computing Team <confidential.computing@intel.com> - 1.25.100.1-1
- Release v1.25
  See release notes at https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.25 for more details and historical changelog
