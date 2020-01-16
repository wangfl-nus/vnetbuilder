#!/bin/bash -x
if [ "$#" -ne "1" ]
then
    echo "$0 SIEM_IP"
    exit 1
fi

SIEM_IP=$1 

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install syslog-ng
echo "source s_snort { file(\"/var/log/error\"
                     follow_freq(1) flags(no-parse) ) ; };

destination d_siem {  tcp(\"$SIEM_IP\") ;
 };
 
 log {
      source(s_snort );
      destination(d_siem);
      flags(flow-control);
 };"| sudo tee --append  /etc/syslog-ng/syslog-ng.conf > /dev/null
sudo service syslog-ng reload

sudo DEBIAN_FRONTEND=noninteractive apt-get -y install snort
echo 'output alert_syslog: LOG_AUTH LOG_ALERT' | sudo tee --append /etc/snort/snort.conf > /dev/null
echo 'alert icmp any any -> $HOME_NET any (msg:"ICMP test detected"; GID:1; sid:10000001; rev:001; classtype:icmp-event;)' | sudo tee --append /etc/snort/rules/local.rules > /dev/null
INTERFACES=`ip addr show | awk '/inet.*brd/{print $NF}'`
for interface in ${INTERFACES}; do
   sudo snort  -u snort -g snort -c /etc/snort/snort.conf -D -i ${interface}
done

echo 'Done.'
