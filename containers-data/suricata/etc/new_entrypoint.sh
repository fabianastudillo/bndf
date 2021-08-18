#!/bin/bash
set -e

fix_perms() {
    if [[ "${PGID}" ]]; then
        groupmod -o -g "${PGID}" suricata
    fi

    if [[ "${PUID}" ]]; then
        usermod -o -u "${PUID}" suricata
    fi

    chown -R suricata:suricata /etc/suricata
    chown -R suricata:suricata /var/lib/suricata
    chown -R suricata:suricata /var/log/suricata
    chown -R suricata:suricata /var/run/suricata
}

for src in /etc/suricata.dist/*; do
    filename=$(basename ${src})
    dst="/etc/suricata/${filename}"
    if ! test -e "${dst}"; then
        echo "Creating ${dst}."
        cp -a "${src}" "${dst}"
    fi
done

/docker-entrypoint.sh
