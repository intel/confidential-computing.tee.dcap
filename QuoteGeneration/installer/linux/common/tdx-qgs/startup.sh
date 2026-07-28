#!/usr/bin/env bash
#
# Copyright (C) 2011-2026 Intel Corporation. All rights reserved.
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

set -e 

QGS_USER=qgsd
QGS_GROUP=qgsd

SYSTEMD_DROPIN_DIR=/etc/systemd/system/qgsd.service.d
SYSTEMD_SOCKET_CONF="${SYSTEMD_DROPIN_DIR}/socket.conf"
UPSTART_CONF=/etc/init/qgsd.conf

# The QCNL collateral cache is created beneath the qgsd user's home directory by the quote provider library.
QGS_CACHE_DIR=/var/opt/qgsd/.dcap-qcnl

if test $(id -u) -ne 0; then
    echo "Root privilege is required."
    exit 1
fi

# Create dedicated, unprivileged user and group for QGS service.
create_qgsd_user_and_group() {
    # Create user and group if not exist
    id -u "${QGS_USER}" &> /dev/null || \
        /usr/sbin/useradd -r -U -c "User for ${QGS_USER}" \
        -d /var/opt/qgsd -s /sbin/nologin "${QGS_USER}"
}

# Bring an existing collateral cache directory in line with the umask policy configured below.
# This is not merely cosmetic: earlier packages ran the daemon under an umask that cleared the owner search bit, leaving the directory as drw-rw----.
# The quote provider only checks that the cache path exists and is a directory, never that it is usable, so it reuses such a directory forever and every cache write keeps failing.
# Correcting the umask alone therefore does not recover an already-affected host; the mode has to be repaired explicitly.
repair_qcnl_cache_dir() {
    # Refuse to touch a symlink: this function runs as root and blindly
    # chmod-ing a symlink target would be a privilege-escalation vector.
    # -d follows symlinks, so check explicitly with -L first.
    if [ -L "${QGS_CACHE_DIR}" ]; then
        echo "Warning: ${QGS_CACHE_DIR} is a symlink; skipping permission repair." >&2
        return 0
    fi

    if [ -d "${QGS_CACHE_DIR}" ]; then
        # Only intervene when the owner search (execute) bit is missing — the
        # exact breakage produced by UMask=0117: mkdir(0777) strips the bit and
        # leaves drw-rw---- which the daemon cannot traverse.
        # If an administrator has deliberately set a different mode (e.g. 0750
        # for monitoring access) we leave it untouched.
        # stat failure (race, stale mount, etc.) is non-fatal: skip the repair
        # rather than aborting the whole installer under set -e.
        current_mode=$(stat -c '%a' "${QGS_CACHE_DIR}" 2>/dev/null) || return 0
        if [ $(( 0${current_mode} & 0100 )) -eq 0 ]; then
            # Add the missing owner search bit and clear group write;
            # leave everything else as the administrator configured it.
            chmod u+x,g-w "${QGS_CACHE_DIR}"
        fi
    fi
}

# Writes a systemd drop-in that gives qgsd a private, auto-cleaned runtime directory and a restrictive default file mode.
# As a result, files the daemon creates stay private to the service user, reducing the attack surface on cached attestation collateral.
configure_systemd_service() {
    # Locate the installed unit file (path varies by distro).
    local unit_file
    unit_file=$(systemctl show -p FragmentPath qgsd 2>/dev/null | cut -d= -f2 || true)
    if [ -z "${unit_file}" ] || [ ! -f "${unit_file}" ]; then
        echo "Warning: qgsd.service not found; skipping drop-in creation." >&2
        return 1
    fi
    mkdir -p "${SYSTEMD_DROPIN_DIR}"

    # Use drop-in rather than patching the unit file directly so that
    # package upgrades can replace the base unit file without losing
    # our overrides.
    tee "${SYSTEMD_SOCKET_CONF}" > /dev/null << 'EOF'
[Service]
RuntimeDirectory=tdx-qgs
# 0755: world-traversable so any local user can reach the socket file
RuntimeDirectoryMode=0755
# The socket mode (0660) is NOT governed by this setting.
# The daemon applies a scoped umask around bind() and an explicit chmod() afterwards, so the socket is 0660 from the instant it appears in the filesystem, whatever UMask= says.
#
# UMask= therefore only affects the daemon's other files, chiefly the QCNL collateral cache under $HOME/.dcap-qcnl.
# It must not be set to the socket's complement (0117): directories are created from a 0777 base, so 0117 strips the owner search bit and produces an unusable drw-rw---- cache directory that the daemon cannot write to or read back.
#
# 0077 yields 0700 directories and 0600 files.
# The service user keeps full access, while the qgsd group - which clients such as QEMU must join in order to connect to the socket - gets no access to cached collateral.
UMask=0077
EOF
}

# Upstart does not support drop-ins, so we must patch the exec line
# in the installed conf file to point at the correct binary location.
# This is done with sed rather than a full rewrite to preserve any
# other customizations an admin may have made to the conf file.
configure_upstart_service() {
    if [ -f "${UPSTART_CONF}" ]; then
        # Skip patching when the exec line already references the
        # correct binary path.
        # This preserves any admin-added flags (e.g. --debug) and
        # makes the operation idempotent across upgrades.
        if grep -qE '^exec \$QGS_PATH/\$NAME' "${UPSTART_CONF}"; then
            return 0
        fi
        # Replace only the binary path (the first token after 'exec'),
        # leaving any trailing arguments the admin may have appended intact.
        sed -i -E "s|^(exec )[^ ]+|\1\$QGS_PATH/\$NAME|" "${UPSTART_CONF}"
    fi
}

# User creation is init-system-agnostic, so do it before branching.
create_qgsd_user_and_group

# Likewise init-system-agnostic, and it must run before the service is (re)started so the daemon comes up with a usable cache directory.
repair_qcnl_cache_dir

# Prefer systemd when available; fall back to Upstart for older distros.
if [ -d /run/systemd/system ]; then
    # Drop-in creation is best-effort: a missing unit file or an
    # unreachable bus must not prevent the service from being enabled
    # and started.
    configure_systemd_service || true
    # Reload so systemd picks up both the base unit and our new drop-in
    # before we try to enable or start the service.
    systemctl daemon-reload
    systemctl enable qgsd
    # 'systemctl restart' handles both the not-running->start and
    # running->restart transitions atomically.
    systemctl restart qgsd
elif [ -d /etc/init/ ]; then
    configure_upstart_service
    # Upstart does not use RuntimeDirectory; create the socket directory
    # here as root before dropping privileges, since qgsd runs as the
    # unprivileged qgsd user and cannot create /run/tdx-qgs itself.
    # Match the systemd path by making the directory world-traversable
    # so any local user can reach the socket file.
    mkdir -p /run/tdx-qgs
    chown "${QGS_USER}:${QGS_GROUP}" /run/tdx-qgs
    chmod 0755 /run/tdx-qgs
    # initctl reload-configuration is the Upstart equivalent of
    # systemctl daemon-reload; required before status/start/restart
    # will reflect the updated conf file.
    /sbin/initctl reload-configuration
    # Unlike systemctl, initctl restart fails if the job is not
    # running; check first.
    if /sbin/initctl status qgsd 2>/dev/null | grep -q 'start/running'; then
        /sbin/initctl restart qgsd
    else
        /sbin/initctl start qgsd
    fi
fi

exit 0
