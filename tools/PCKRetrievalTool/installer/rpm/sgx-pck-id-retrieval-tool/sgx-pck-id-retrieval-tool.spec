#
# Copyright(c) 2011-2025 Intel Corporation
#
# SPDX-License-Identifier: BSD-3-Clause
#


%define _install_path @install_path@

Name:           sgx-pck-id-retrieval-tool
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) Software Guard Extensions:this tool is used to collect the platform information to retrieve the PCK certs from PCS(Provisioning Certification Server)
Group:          Development/System
Recommends:     libsgx-urts >= 2.27, libsgx-ae-pce >= %{version}-%{release}, libsgx-ae-id-enclave >= %{version}-%{release},libsgx-ra-uefi >= %{version}-%{release}
Suggests:       intel-tee-pcs-client-tool >= %{version}-%{release}

License:        BSD License
URL:            https://github.com/intel/SGXDataCenterAttestationPrimitives
Source0:        %{name}-%{version}.tar.gz

%description
Intel(R) Software Guard Extensions:this tool is used to collect the platform information to retrieve the PCK certs from PCS(Provisioning Certification Server)

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
echo "%{_install_path}" > %{_specdir}/list-%{name}
find %{?buildroot} | sort | \
awk '$0 !~ last "/" {print last} {last=$0} END {print last}' | \
sed -e "s#^%{?buildroot}##" | \
grep -v "^%{_install_path}" >> %{_specdir}/list-%{name} || :
sed -i 's#^/etc/rad.conf#%config &#' %{_specdir}/list-%{name}

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

%posttrans
################################################################################
# Set up SGX pck cert id retrieve tool                                         #
################################################################################

# Install the SGX_PCK_ID_RETRIEVE_TOOL 
ln -s -f /opt/intel/sgx-pck-id-retrieval-tool/PCKIDRetrievalTool /usr/local/bin/PCKIDRetrievalTool
retval=$?

if test $retval -ne 0; then
    echo "failed to install $SGX_PCK_ID_RETRIEVE_TOOL_NAME."
    exit 6
fi

echo -e "Installation succeed!"

%postun

# Removing SGX_PCK_ID_RETRIEVE_TOOL soft link file
rm -f /usr/local/bin/PCKIDRetrievalTool

echo -e "Uninstallation succeed!"

%changelog
* Mon Apr 28 2020 SGX Team
- Initial Release
