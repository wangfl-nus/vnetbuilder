#!/bin/bash -x
if [ "$#" -eq "5" ]; then
    VM_NAME=$1
    NODE_NAME=$2
    EXP_NAME=$3
    TEAM_NAME=$4
    SIEM_IP=$5
    
    cp /share/ven/soft/build.snort.i.sh /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/

    echo "/vagrant/build.snort.i.sh $SIEM_IP" | ssh $VM_NAME
elif [ "$#" -eq "1" ]; then
    source /share/ven/soft/build.snort.i.sh $VM_IP
else
    echo "$0 vm_name node_name experiment_name team_name siem_ip#For install on vm"
    echo "$0 siem_ip#For intall on this node"
    exit 1
fi
echo 'Done.'
