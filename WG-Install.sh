echo "Welcome to the WireGuard installer!"

# Detect public IPv4 or IPv6 address and pre-fill for the user
read -rp "IPv4 or IPv6 public address: " -e SERVER_PUB_IP

# Detect public interface and pre-fill for the user
SERVER_NIC="$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)"
until [[ ${SERVER_PUB_NIC} =~ ^[a-zA-Z0-9_]+$ ]]; do
	read -rp "Public interface: " -e -i "${SERVER_NIC}" SERVER_PUB_NIC
done

until [[ ${SERVER_WG_NIC} =~ ^[a-zA-Z0-9_]+$ && ${#SERVER_WG_NIC} -lt 16 ]]; do
	read -rp "WireGuard interface name: " -e -i wg0 SERVER_WG_NIC
done

until [[ ${SERVER_WG_IPV4} =~ ^([0-9]{1,3}\.){3} ]]; do
	read -rp "Server's WireGuard IPv4: " -e SERVER_WG_IPV4
done

# UDP port
until [[ ${SERVER_PORT} =~ ^[0-9]+$ ]] && [ "${SERVER_PORT}" -ge 1 ] && [ "${SERVER_PORT}" -le 65535 ]; do
	read -rp "Server's WireGuard port [1-65535]: " -e -i 51820 SERVER_PORT
done

# DNS 
until [[ ${CLIENT_DNS_1} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
	read -rp "First DNS resolver to use for the clients: " -e CLIENT_DNS_1
done
until [[ ${CLIENT_DNS_2} =~ ^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$ ]]; do
	read -rp "Second DNS resolver to use for the clients (optional): " -e CLIENT_DNS_2
	if [[ ${CLIENT_DNS_2} == "" ]]; then
		CLIENT_DNS_2="${CLIENT_DNS_1}"
	fi
done

# remote subnets
echo "Please provide the subnets in CDIR notation, separated with a comma"
read -rp "[Like 10.199.240.0/24,10.199.241.0/24]: " -e REMOTE_SUBNETS


echo ""
echo "Okay, that was all I needed. We are ready to setup your WireGuard server now."
read -n1 -r -p "Press any key to continue..."

# Install WireGuard tools and module
apt-get update
apt-get install -y wireguard iptables resolvconf git python3 pip gunicorn htop apt-transport-https open-vm-tools dnsutils net-tools auditd sysstat lynis mailutils rsync sudo

#echo "nameserver 87.249.99.21
#nameserver 87.249.96.111
#nameserver 87.249.99.6" > /etc/resolv.conf

echo "alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'" >> /root/.bashrc

echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.d/ipv6.conf

sed -i 's/rotate 4/rotate 32/' /etc/logrotate.d/rsyslog
sed -i 's/weekly/daily/' /etc/logrotate.d/rsyslog

echo "NTP=pool.ntp.org
FallbackNTP=0.nl.pool.ntp.org 1.nl.pool.ntp.org 2.nl.pool.ntp.org" >> /etc/systemd/timesyncd.conf


# Make sure the directory exists (this does not seem the be the case on fedora)
mkdir /etc/wireguard >/dev/null 2>&1

chmod 600 -R /etc/wireguard/

SERVER_PRIV_KEY=$(wg genkey)
SERVER_PUB_KEY=$(echo "${SERVER_PRIV_KEY}" | wg pubkey)

# Save WireGuard settings
echo "SERVER_PUB_IP=${SERVER_PUB_IP}
SERVER_PUB_NIC=${SERVER_PUB_NIC}
SERVER_WG_NIC=${SERVER_WG_NIC}
SERVER_WG_IPV4=${SERVER_WG_IPV4}
SERVER_PORT=${SERVER_PORT}
SERVER_PRIV_KEY=${SERVER_PRIV_KEY}
SERVER_PUB_KEY=${SERVER_PUB_KEY}
CLIENT_DNS_1=${CLIENT_DNS_1}
CLIENT_DNS_2=${CLIENT_DNS_2}
REMOTE_SUBNETS=${REMOTE_SUBNETS}" >/etc/wireguard/params

# Add server interface
echo "[Interface]
Address = ${SERVER_WG_IPV4}/24
ListenPort = ${SERVER_PORT}
PrivateKey = ${SERVER_PRIV_KEY}" >"/etc/wireguard/${SERVER_WG_NIC}.conf"


echo "PostUp = iptables -A FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -A FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -A POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE
PostDown = iptables -D FORWARD -i ${SERVER_PUB_NIC} -o ${SERVER_WG_NIC} -j ACCEPT; iptables -D FORWARD -i ${SERVER_WG_NIC} -j ACCEPT; iptables -t nat -D POSTROUTING -o ${SERVER_PUB_NIC} -j MASQUERADE" >>"/etc/wireguard/${SERVER_WG_NIC}.conf"


# Enable routing on the server
echo "net.ipv4.ip_forward = 1" >/etc/sysctl.d/wg.conf

sysctl --system

systemctl start "wg-quick@${SERVER_WG_NIC}"
systemctl enable "wg-quick@${SERVER_WG_NIC}"


git clone -b v3.0.6 https://github.com/donaldzou/WGDashboard.git wgdashboard
cd wgdashboard/src
sudo chmod u+x wgd.sh
sudo ./wgd.sh install
sudo chmod -R 755 /etc/wireguard

sed -i 's/^app_port.*/app_port = 80/' wg-dashboard.ini
sed -i 's/^peer_global_dns.*/peer_global_dns = ${CLIENT_DNS_1}/' wg-dashboard.ini
sed -i 's/^remote_endpoint.*/remote_endpoint = ${SERVER_PUB_IP}/' wg-dashboard.ini
sed -i 's~^peer_endpoint_allowed_ip.*~peer_endpoint_allowed_ip = ${REMOTE_SUBNETS}~' wg-dashboard.ini


echo "[Unit]
After=netword.service

[Service]
WorkingDirectory=/root/wgdashboard/src
ExecStart=/usr/bin/python3 /root/wgdashboard/src/dashboard.py
Restart=always


[Install]
WantedBy=default.target" > wg-dashboard.service

cp wg-dashboard.service /etc/systemd/system/wg-dashboard.service

chmod 664 /etc/systemd/system/wg-dashboard.service
systemctl daemon-reload
systemctl enable wg-dashboard.service
systemctl start wg-dashboard.service  # <-- To start the service

echo "Time for a reboot, don't forget to add your user to the sudoers group"
reboot
