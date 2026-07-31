#
# Copyright(c) 2011-2026 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#

%define _install_path @install_path@

Name:           tdx-qgs
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) TD Quoting Generation Service
Group:          Development/System
Requires:       libsgx-tdx-logic >= %{version}-%{release}

License:        BSD License
URL:            https://github.com/intel/SGXDataCenterAttestationPrimitives
Source0:        %{name}-%{version}.tar.gz

%description
Intel(R) TD Quoting Generation Service

%prep
%setup -qc

%build
make %{?_smp_mflags}

%install
make DESTDIR=%{?buildroot} install
echo "%{_install_path}" > %{_specdir}/list-%{name}
find %{?buildroot} | sort | \
awk '$0 !~ last "/" {print last} {last=$0} END {print last}' | \
sed -e "s#^%{?buildroot}##" | \
grep -v "^%{_install_path}" | \
grep -v "^/etc/qgs\.conf" >> %{_specdir}/list-%{name} || :

%files -f %{_specdir}/list-%{name}
%config(noreplace) /etc/qgs.conf

%posttrans
if [ -x %{_install_path}/startup.sh ]; then %{_install_path}/startup.sh; fi

%preun
if [ -x %{_install_path}/cleanup.sh ]; then %{_install_path}/cleanup.sh; fi

%changelog
* @date@ Intel Confidential Computing Team <confidential.computing@intel.com> - @version@-1
- Release v1.27
  See https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.27 for full release notes.

- Key changes:
  1. qgsd QCNL collateral cache umask tightened from 022 to 077;
     the cache directory (/var/opt/qgsd/.dcap-qcnl) is now private to the qgsd
     service user. Processes reading the cache as a non-qgsd user will fail.
     Existing directories with a broken mode are repaired automatically during
     package upgrade.

* Thu Apr 30 2026 Intel Confidential Computing Team <confidential.computing@intel.com> - 1.26.100.1-1
- Release v1.26
  See https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.26 for full release notes.

- Key changes:
  1. [BREAKING] Unix domain socket is now the default transport; existing deployments
     relying on vsock must explicitly re-add 'port=<n>' to /etc/qgs.conf.
  2. /etc/qgs.conf is preserved across RPM upgrades (%%config(noreplace)).
  3. Socket directory and file are created with correct ownership
     (qgsd:qgsd) and permissions (dir 0755, socket 0660).
     Any user or service that needs to communicate with QGS over the
     Unix domain socket must be a member of the qgsd group:
       usermod -aG qgsd <username>
  4. startup.sh writes a systemd drop-in to set RuntimeDirectory=tdx-qgs
     so systemd manages the socket directory lifecycle.
  5. Stale socket files from a prior unclean shutdown are automatically cleaned up
     on startup.

* Wed Mar 04 2026 Intel Confidential Computing Team <confidential.computing@intel.com> - 1.25.100.1-1
- Release v1.25
  See release notes at https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.25 for more details and historical changelog
