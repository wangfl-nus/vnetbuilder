#!/bin/bash -x
if [ "$#" -eq "4" ]; then
    VM_NAME=$1
    NODE_NAME=$2
    EXP_NAME=$3
    TEAM_NAME=$4

    DEFAULT_USERS=default_users.json
    DEFAULT_VSFTPD_CFG=default_vsftpd.conf
    cp /share/ven/soft/$DEFAULT_USERS /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
    cp /share/ven/soft/$DEFAULT_VSFTPD_CFG /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
    cp /share/ven/soft/addusers.py /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/    
    cp /share/ven/soft/build.ftp.i.sh /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/    
    echo "/vagrant/build.ftp.i.sh /vagrant/$DEFAULT_USERS" | ssh $VM_NAME
elif [ "$#" -eq "0" ]; then
    DEFAULT_USERS=default_users.json
    /vagrant/build.ftp.i.sh /share/ven/soft/$DEFAULT_USERS
else
    echo "$0 vm_name node_name experiment_name team_name #For install on vm"
    echo "$0 #For intall on this node"
    exit 1
fi
echo 'Done.'
