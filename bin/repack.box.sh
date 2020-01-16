#!/bin/bash -x
SHELL_VM="! grep vagrant /etc/passwd && adduser vagrant;
cd ~vagrant;
! ls .ssh && mkdir .ssh ;
! ls .ssh/authorized_keys && touch .ssh/authorized_keys ;
! sudo grep 'vagrant ALL=(ALL) NOPASSWD: ALL' /etc/sudoers && echo -e '\nvagrant ALL=(ALL) NOPASSWD: ALL' | sudo tee --append /etc/sudoers ;
! grep 'AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltG' .ssh/authorized_keys && echo 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6NF8iallvQVp22WDkTkyrtvp9eWW6A8YVr+kz4TjGYe7gHzIw+niNltGEFHzD8+v1I2YJ6oXevct1YeS0o9HZyN1Q9qgCgzUFtdOKLv6IedplqoPkcmF0aYet2PkEDo3MlTBckFXPITAMzF8dJSIFo9D8HfdOV0IAdx4O7PtixWKn5y2hMNG0zQPyUecp4pzC6kivAIhyfHilFR61RGL+GPXQ2MWZWFYbAGjyiYJnAmCP3NOTd0jMZEnDkbUvxhMmBYSdETk1rRgm+R4LOzFUGaHqHDLKLX+FIPKcF96hrucXzcWyLbIbEgE98OHlnVYCzRdK8jlqm8tehUc9c9WhQ== vagrant insecure public key
'>>.ssh/authorized_keys ;
sudo apt-get clean ;
cat /dev/null > ~/.bash_history && history -c && exit; "

if [ "$#" -eq "3" ]; then
    VM_NAME=$1
    BOX_FILE_NAME=$2
    BOX_NAME=$3

    echo "hostname" | ssh $VM_NAME
    if [ "$?" -ne "0" ]; then
        exit 1
    fi
    echo $SHELL_VM | ssh $VM_NAME
    vagrant package --output $BOX_FILE_NAME --base $VM_NAME
    vagrant box add $BOX_NAME $BOX_FILE_NAME

elif [ "$#" -eq "5" ]; then
    USER_HOST=$1
    VM_SSH_PORT=$2
    VM_NAME=$3
    BOX_FILE_NAME=$4
    BOX_NAME=$5

    echo "hostname" | ssh $USER_HOST -p $VM_SSH_PORT
    if [ "$?" -ne "0" ]; then
        exit 1
    fi
    echo $SHELL_VM | ssh $USER_HOST -p $VM_SSH_PORT
    vagrant package --output $BOX_FILE_NAME --base $VM_NAME
    vagrant box add $BOX_NAME $BOX_FILE_NAME

else
    echo "$0 vm_name BOX_FILE_NAME BOX_NAME #For vagrant package box based on VM_NAME"
    echo "$0 username@host port vm_name BOX_FILE_NAME BOX_NAME #For vagrant package box based on VM_NAME"
    exit 1
fi
echo 'Done.'


