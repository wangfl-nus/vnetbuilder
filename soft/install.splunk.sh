#!/bin/bash -x
if [ "$#" -eq "4" ]; then
    VM_NAME=$1
    NODE_NAME=$2
    EXP_NAME=$3
    TEAM_NAME=$4

    FILE=splunklight-7.0.0-c8a78efdd40f-linux-2.6-amd64.deb
    cp -n /share/ven/soft/$FILE /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
    cp -n /share/ven/soft/build.splunk.i.sh /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/

    ssh $VM_NAME "/vagrant/build.splunk.i.sh /vagrant/$FILE" 
elif [ "$#" -eq "0" ]; then
        /vagrant/build.splunk.i.sh /share/ven/soft/$FILE
else
    echo "$0 vm_name node_name experiment_name team_name #For install on vm"
    echo "$0 #For intall on this node"
    exit 1
fi
echo 'Done.'

