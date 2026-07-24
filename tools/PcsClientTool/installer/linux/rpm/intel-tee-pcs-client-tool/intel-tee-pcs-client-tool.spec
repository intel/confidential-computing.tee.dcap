#
# Copyright(c) 2025 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause
#

%define _install_path @install_path@
%define _venv_dir @install_path@/.venv
%define _main_script_name @main_script_name@
%define _wrapper_script_name @pkg_wrapper_script_name@
%define _license_file COPYING
%define python_interpreter python3

Name:           intel-tee-pcs-client-tool
Version:        @version@
Release:        1%{?dist}
Summary:        Intel(R) SGX and Intel(R) TDX Provisioning Certification Service (Intel PCS) Client Tool
Group:          Applications/Internet

Requires: bash, coreutils

#PYTHON dependencies - BEGIN
# OpenSuse Leap15 and Anolis have 2 interpreters (with global one stuck at 3.6 which is too low for us): https://en.opensuse.org/openSUSE:Packaging_Python
%if 0%{?sle_version} >= 150000 || 0%{?anolis_ver} >= 8

# When building outside of OBS (locally with rpmbuild), the extra macros are not defined, hence the default for python311 (valid for SLE15 Leap 15.x)
%{!?single_pythons_311plus: %define single_pythons_311plus python311}
%{!?primary_python: %define primary_python python3.11}
%define python_interpreter %{primary_python}

%if 0%{?sle_version} != 0
# OpenSuse >=15
Requires:       %{?single_pythons_311plus} >= 3.7, %{?single_pythons_311plus}-pip
%else
# Anolis >= 8
Requires:       %{?single_pythons_311plus} >= 3.7
%endif
%else
# Non-SLES>15.x && Non-Anolis>8.x
Requires:       python3 >= 3.7 python3-pip
%endif
#PYTHON dependencies - END

Provides:       %{_wrapper_script_name}

# pccs-admin-tool is a weak reverse dependency aka. reverse hint (not installed by default by package managers).
#    It is reflected only to document the relationship between the 2 tools and that they can work in tandem in for certain air-gapped scenarios.
#    Note the `pcs-client-tool` is perfectly-standalone for non-PCCS use cases.
# Similarly, in a non-PCCS use case, the pcs-client-tool works in concert with PCKIDRetrievalTool (inputs producer) and the default QPL/QCNL (cache file consumer).
Enhances: intel-tee-pccs-admin-tool >= %{version}-%{release}, sgx-pck-id-retrieval-tool >= %{version}-%{release}, libsgx-dcap-default-qpl >= %{version}-%{release}

Vendor:         Intel Corporation
License:        BSD License
URL:            https://github.com/intel/SGXDataCenterAttestationPrimitives
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

%description
This package provides the %{_wrapper_script_name} executable (python script) for interacting with the Intel PCS web service REST API.

%prep
%setup -qc

%install
make DESTDIR=%{?buildroot} install
install -d %{?buildroot}%{_docdir}/%{name}
find linux/installer/common/sdk/output/package/licenses/ -type f -print0 | \
    xargs -0 -n1 cat >> %{?buildroot}%{_docdir}/%{name}/%{_license_file}
find %{?buildroot} -type d -links 2 | \
    sed -e "s#^%{?buildroot}##" | \
    grep -v "^%{_libdir}" | \
    grep -v "^%{_bindir}" | \
    grep -v "^%{_sysconfdir}" | \
    grep -v "^%{_install_path}" | \
    sed -e "s#^#%dir #" > %{_specdir}/listfiles
for f in $(find %{?buildroot}); do
    if [ -d ${f} ]; then
        echo ${f} | \
        sed -e "s#^%{?buildroot}##" | \
        grep "^%{_install_path}" | \
        sed -e "s#^#%dir #" >> %{_specdir}/listfiles
    else
        echo ${f} | \
        sed -e "s#^%{?buildroot}##" >> %{_specdir}/listfiles
    fi
done

%files -f %{_specdir}/listfiles



%post -p /bin/bash
set -euo pipefail

function on_pip_error() {
    error_code=$?
    if [[ "${pip_output:-}" == *Network* ]] || [[ "${pip_output:-}" == *ProxyError* ]] || [[ "${pip_output:-}" == *NewConnectionError* ]] || [[ "${pip_output:-}" == *SSLError* ]]; then
        echo -e "ERROR: 'pip install' failed with exit code $error_code. See the %post scriptlet output above for details.\n"
        echo "Note: If the issue is network-related and you are behind a network proxy, please check your system configuration (e.g., proxy related environment variables)."
        echo "      For example, try retrying the command with explicit proxy, i.e. #> https_proxy=http://proxy.example.com:1234 dnf install intel-tee-pcs-client-tool"
        echo "      For more information, see: https://pip.pypa.io/en/stable/user_guide/#using-a-proxy-server"
        echo "      Detected proxy variables: 'http_proxy': [${http_proxy:-not set}] | 'https_proxy': [${https_proxy:-not set}] | 'no_proxy': [${no_proxy:-not set}] | 'PIP_PROXY': [${PIP_PROXY:-not set}]"        
    fi
    exit ${error_code}
}

if [ -d "%{_venv_dir}" ]; then
    echo "Removing old virtual environment at %{_venv_dir}"
    rm -rf "%{_venv_dir}"
fi
echo "Creating virtual environment..."
%{python_interpreter} -m venv "%{_venv_dir}"

echo "Activating virtual environment and installing dependencies..."
source "%{_venv_dir}/bin/activate"

OUT_STREAM=$( [ -t 1 ] && [ -e /dev/tty ] && [ -w /dev/tty ] && echo /dev/tty || echo /dev/stderr )
trap 'on_pip_error' ERR  # To inject extra error handling for proxy

# Deliberately set low timeouts and retries to avoid long hangs during installation (overridable via env vars)
export PIP_TIMEOUT=${PIP_TIMEOUT:-5}
export PIP_RETRIES=${PIP_RETRIES:-1}

pip_output=$(pip install --no-input --require-virtualenv --upgrade pip 2>&1 | tee ${OUT_STREAM})
pip_output=$(pip install --no-input --require-virtualenv --upgrade setuptools wheel 2>&1 | tee ${OUT_STREAM})

echo "Installing required Python packages:"
cat "%{_install_path}/requirements.txt"
pip_output=$(pip install --no-input --require-virtualenv -r "%{_install_path}/requirements.txt" 2>&1 | tee ${OUT_STREAM})

trap - ERR

echo "Virtual environment setup complete."


%posttrans
# Note: due to a broken package in 1.24 release (which deletes these files unconditionally in %preun which runs after %post (new),
#        we're installing them at the end of transaction).
#       If this is ever deemed too late, it can be moved back inside %post, but only AFTER 1.24 release is out of support.
echo -n "Creating wrapper script at '%{_install_path}/%{_wrapper_script_name}' and linking to /usr/local/bin/..."

cat <<EOF > "%{_install_path}/%{_wrapper_script_name}"
#!/usr/bin/env bash
source "%{_venv_dir}/bin/activate"
PCS_CLIENT_TOOL_EXECUTABLE_WRAPPER=%{_wrapper_script_name} PYTHONPYCACHEPREFIX="%{_venv_dir}/__pycache__" python "%{_install_path}/%{_main_script_name}" "\$@"
EOF

chmod +x "%{_install_path}/%{_wrapper_script_name}"
# Add the wrapper script to a directory in the user's PATH, e.g., /usr/local/bin
ln -sf "%{_install_path}/%{_wrapper_script_name}" /usr/local/bin/%{_wrapper_script_name}
echo "DONE"
echo "Installation successful. Run \`%{_wrapper_script_name}\` to start using the tool."


%preun
# Note this cleanup part runs also on upgrade path (after the %post of the new package), so that we always start without cached files in a fresh venv, similar to DEB installer logic
#
if [ -d "%{_install_path}" ]; then
    #remove any __pycache__ remnant dirs which may have been created in "wrong" location if user launched the script w/o wrapper script
    find "%{_install_path}" -type d -name "__pycache__" -exec rm -rf {} +
else
    echo "Installation path %{_install_path} does not exist. Skipping __pycache__ removal."
fi

if [ $1 -ne 0 ]; then
    # On upgrade path, we stop the cleanup here
    exit 0
fi

if [ -d "%{_venv_dir}" ]; then
    echo "Removing virtual environment at %{_venv_dir}"
    rm -rf "%{_venv_dir}"
    echo "Virtual environment removed."
else
    echo "No virtual environment found at %{_venv_dir}. Skipping its removal."
fi

if [ -f "%{_install_path}/%{_wrapper_script_name}" ]; then
    rm -f "%{_install_path}/%{_wrapper_script_name}"
else
    echo "No wrapper script found at %{_install_path}/%{_wrapper_script_name}. Skipping its removal."
fi

# remove the symlink from /usr/local/bin
if [ -L "/usr/local/bin/%{_wrapper_script_name}" ]; then
    echo "Removing symlink /usr/local/bin/%{_wrapper_script_name}"
    rm -f "/usr/local/bin/%{_wrapper_script_name}"
    echo "Symlink removed."
else
    echo "No symlink found at /usr/local/bin/%{_wrapper_script_name}. Skipping its removal."
fi

if [ $1 == 0 -a -x %{_install_path}/cleanup.sh ]; then %{_install_path}/cleanup.sh; fi


%changelog
* @date@ Intel Confidential Computing Team <confidential.computing@intel.com> - @version@-1
- Release v1.27
  See https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.27 for full release notes.

* Thu Apr 30 2026 Intel Confidential Computing Team <confidential.computing@intel.com> - 1.26.100.1-1
- Release v1.26
  See https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.26 for full release notes.

* Wed Mar 04 2026 Intel Confidential Computing Team <confidential.computing@intel.com> - 1.25.100.1-1
- Release v1.25
  See https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.25 for full release notes.
- Key changes:
  1. Installer: moved Python Virtual Environment to '.venv' and fixed version upgrade path (%preun upgrade guard)

* Wed Oct 01 2025 Intel Confidential Computing Team <confidential.computing@intel.com> - 1.24.100.2-1
- Release v1.24
  See https://github.com/intel/confidential-computing.tee.dcap/releases/tag/DCAP_1.24 for full release notes.
- Key changes:
  1. Initial packaged release of pcsclient.py. Follows the former (all-in-one) pccsadmin.py tool split into (PCCS-specific) pccsadmin.py and (generic) pcsclient.py
