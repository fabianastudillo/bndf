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

cat <<EOF >>/root/capture-filter.bpf
not host 201.159.221.68
not host 201.159.221.73
not host 201.159.221.74
not host 201.159.221.78
not host 201.159.221.80
not host 2800:0068:0000:bebe:0000:0000:0000:0004
not host 2800:0068:0000:caff:80f2:a0e4:f282:178f
not host 2800:0068:000e:0000:0000:0000:0000:0222
not host 2800:0130:0001:0050:0209:6bff:fef1:c314
not host 2800:0130:0001:0050:0250:56ff:febd:5fd5
not host 2801:0016:4800:0002:0000:0000:0102:0039
EOF

/docker-entrypoint.sh
