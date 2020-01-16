#!/bin/bash -x
if [ "$#" -eq "4" ]; then
    VM_NAME=$1
    NODE_NAME=$2
    EXP_NAME=$3
    TEAM_NAME=$4

    JARFILE=webgoat-server-8.0.0.RELEASE.jar
    cp /share/ven/soft/$JARFILE /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
    cp /share/ven/soft/build.webgoat.sh /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/

    echo "/vagrant/build.webgoat.i.sh /vagrant/$JARFILE" | ssh $VM_NAME
elif [ "$#" -eq "0" ]; then
        /vagrant/build.webgoat.i.sh /share/ven/soft/$JARFILE
else
    echo "$0 vm_name node_name experiment_name team_name #For install on vm"
    echo "$0 #For intall on this node"
    exit 1
fi
echo 'Done.'

