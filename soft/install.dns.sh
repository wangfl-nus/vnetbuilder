#!/bin/bash -x
if [ "$#" -eq "5" ]; then
    VM_NAME=$1
    NODE_NAME=$2
    EXP_NAME=$3
    TEAM_NAME=$4
	VM_IP=$5
	DOMAIN=$EXP_NAME.$TEAM_NAME.ncl.sg
    
	cp /proj/$TEAM_NAME/$EXP_NAME/hosts.txt /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
    cp /share/ven/soft/build.dns.i.sh /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/

    echo "/vagrant/build.dns.i.sh $DOMAIN $VM_IP" | ssh $VM_NAME
elif [ "$#" -eq "1" ]; then
        /vagrant/build.dns.i.sh $VM_IP
else
    echo "$0 vm_name node_name experiment_name team_name vm_ip#For install on vm"
    echo "$0 vm_ip#For intall on this node"
    exit 1
fi
echo 'Done.'
