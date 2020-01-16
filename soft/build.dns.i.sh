#!/bin/bash
if [ "$#" -ne 2 ]
then
    echo "$0 domain_name dns_server_ip"
    exit 1
fi

domainame=$1
ipadd=$2

sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y ugrade
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install bind9 bind9-doc bind9utils
echo "Updation and installation is completed"
#else  
#echo "Bind9 already instaled"
#fi
#fi
if [ ! -d "/etc/bind" ]; then
    sudo mkdir /etc/bind
fi
sudo rm /etc/bind/named.conf
sudo touch /etc/bind/named.conf
sudo chmod 777 /etc/bind/named.conf

if [ ! -d "/var/named/" ]; then
 sudo mkdir /var/named/
fi
sudo touch /var/named/AddDomain
sudo chmod 777 /var/named/AddDomain

if [ ! -d "/var/log/named/" ]; then
  sudo mkdir /var/log/named/
fi 
sudo chmod 777 /var/log/named/

sudo touch /var/log/named/dns_log
sudo chmod 777 /var/log/named/dns_log
NAMED_CONF_PATH="/etc/bind/named.conf"  # named.conf file location with path
BIND_DB_PATH="/etc/bind"          # do not append / at the end
#DNS_LOG_PATH="/var/log/dns_log" # logging of dns queries in dns_log file
APPAR_WR_PATH="/etc/apparmor.d/usr.sbin.named"
SERIAL_NO_COUNT="/var/named/AddDomain" # Where to get serial number count
#MAIL_SERVER="mail.ecyberciti.com." # MX Pointer i.e. All Mail forword to this
                                  # domain will goes to this mail server
#NS1="ns1.$domainame."          # First Name Server  
#NS2="ns2.ecyberciti.com."      # Second Name Server
#ADMIN_EMAIL="hostmaster.ecyberciti.com." # Hostmaster e-mail ID
# Input for - UDVs
ZONE_DB="" 
ZONE_DB1=""
#domainame=""
#ipadd=""
hostnam=""
hostIP=""
last2byte=""
serial_no=1                     # Default
# Main script begins here
#echo -n "Enter Domain Name : "
#read domainame
#if [ -d "$BIND_DB_PATH/$domainame.zone" ]; then
sudo rm "$BIND_DB_PATH/$domainame.zone"
sudo touch "$BIND_DB_PATH/$domainame.zone"
#fi
#if [ -d $$BIND_DB_PATH/rev.$domainame.zone ]; then
sudo rm "$BIND_DB_PATH/rev.$domainame.zone"
sudo touch "$BIND_DB_PATH/rev.$domainame.zone"
#fi

ZONE_DB="$BIND_DB_PATH/$domainame.zone"
ZONE_DB1="$BIND_DB_PATH/rev.$domainame.zone"
#echo -n "Enter IP Address for $domainame : "
#read ipadd
#
# Find the serial_no count for domain
#
if ! [ -f $SERIAL_NO_COUNT ] ; then
   echo "Init... Serial Number count to default 1"
   echo "1" > $SERIAL_NO_COUNT
   serial_no=1
else # get the last time saved serial_no count
   serial_no=`cat $SERIAL_NO_COUNT`
   serial_no=`expr $serial_no + 1`
   echo "$serial_no" > $SERIAL_NO_COUNT
fi
#
# See if domain alrady exists or not
#
if  grep \"$domainame\" $NAMED_CONF_PATH > /dev/null  ; then
    echo "Domain $domainame already exists, please try another domain"
    exit 1
fi
#
# Make sure its valid IP Address
#  
if which ipcalc > /dev/null ; then
 ipcalc -ms $ipadd > /dev/null 
 if ! [ $? -eq 0 ] ; then
    echo -e "*** Bad ip address: $ipadd\nTry again with correct IP Address."
    exit 2
 fi
else
  echo "Warning can't validate the IP Address $ipadd"
fi
#
# Open the named.conf file and append the entries
echo "acl "trusted" {
	  172.16.0.0/24;
	};
  options {
	listen-on port 53 { $ipadd; any; };
	directory \"/etc/bind\";
	allow-query { $ipadd; any; };
	allow-transfer { none; };
	recursion yes;
	allow-recursion { any; };
forwarders {
	10.64.0.6;
	8.8.8.8;
	8.8.4.4;
	};
	dnssec-validation no;
	auth-nxdomain no;
	listen-on-v6 { any; };
	};
zone  \"$domainame\" {
       		type master;  
       		file \"/etc/bind/$domainame.zone\";
	     	allow-update { key $domainame; };
		};
zone  \"16.172.in-addr.arpa\" {
       		type master;  
       		file \"/etc/bind/rev.$domainame.zone\";
	    	allow-update { key $domainame; }; 
		}; 
key rndc-key {
	 algorithm hmac-md5;
	 secret \"/RketiReUTVAZEmslJcFZQ==\";
	};
controls {
	inet 127.0.0.1 port 953
	allow { 127.0.0.1; } 
	keys { "rndc-key"; };
	};
 logging {
	channel dns_log {
	file \"/var/log/named/dns_log\";
	severity info;
	print-category yes;
	print-severity yes;
	print-time yes;
	};
	category default { dns_log; };	
	category update { dns_log; };
	category update-security { dns_log; };
	category security { dns_log; };
	category queries { dns_log; };
	category lame-servers { dns_log; };
	}; " >> $NAMED_CONF_PATH
#
# Crate zone file for domain
#
echo "\$TTL 604800
@  IN  SOA  $domainame.  root.$domainame.  (
               $serial_no        ;serial
               604800            ;refresh
               86400             ;retry
               2419200           ;expire
               604800            ;TTL
               )
;
;Name Servers
@             IN        NS        $domainame.
;
;IP addresses $domainame 
@	IN	A	$ipadd
www	IN	A	$ipadd " | sudo tee -a $ZONE_DB
#adding host in the zone file 
while IFS=, read -r hostnam hostIP; do
echo "$hostnam.$domainame. IN 	A $hostIP " | sudo tee -a $ZONE_DB
done < "$(dirname -- "$0")/hosts.txt"					
#
#Create reverse zone file for domain
#
echo "\$TTL 604800
@  IN  SOA  $domainame.  root.$domainame.  (
               $serial_no        ;serial
               604800            ;refresh
               86400             ;retry
               2419200           ;expire
               604800            ;TTL
               )
;
;Name servers records
@		IN      NS      $domainame.
@		IN	A	$ipadd
;PTR records "  | sudo tee -a $ZONE_DB1
#Adding PTR for host. 
#First need to reverse last 2 bytes of hostIP. The reverseip function is as follows
reverseip() {
local IFS
IFS=.
set -- $1
echo $4.$3
}
echo "$(reverseip $ipadd)	IN PTR	$domainame. ; $ipadd " | sudo tee  $ZONE_DB1
while IFS=, read -r hostnam hostIP; do
echo "$(reverseip $hostIP) IN PTR $hostnam.$domainame. ;$hostIP"  | sudo tee -a $ZONE_DB1
done < "$(dirname -- "$0")/hosts.txt"
echo "nameserver $ipadd
search $domainame" | sudo tee /etc/resolv.conf
echo "$domainame ($ipadd) Addedd successfully."
sudo service bind9 restart
echo "Restarting bind9..."
# service bind9 status

