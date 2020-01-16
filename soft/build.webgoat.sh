#!/bin/bash -x
if [ "$#" -ne "4" ]
then
    echo "$0 vm_name node_name experiment_name team_name"
    exit 1
fi
VM_NAME=$1
NODE_NAME=$2
EXP_NAME=$3
TEAM_NAME=$4

OWNER=ntechni3
JARFILE=webgoat-server-8.0.0.RELEASE.jar
cp /share/ven/soft/$JARFILE /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
CMD4VM="hostname
echo 'here'
sudo apt-get update
sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install default-jre
sudo java -Djava.net.preferIPv4Stack=true -jar /vagrant/webgoat-server-8.0.0.RELEASE.jar &"
echo "$CMD4VM" | ssh $VM_NAME



