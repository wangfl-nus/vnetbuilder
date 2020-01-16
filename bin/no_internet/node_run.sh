#!/bin/bash -x
if [ "$#" -lt "3" ] || [ "$#" -gt "4" ]
then
    echo "$0 node_name experiment_name team_name gateway_ip"
    exit 1
fi

NODE_NAME=$1
EXP_NAME=$2
TEAM_NAME=$3
GATEWAY_IP=$4
OWNER=$USER

LEAD="### BEGIN NCL ADD CONTENT"
TAIL="### END NCL ADD CONTENT"

# install virtual box function
# virtualbox 5.2
install_virtualbox() {
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y install /share/ven/soft/virtualbox-5.2.deb
    vboxmanage setproperty machinefolder /mnt/sda3/vm
}

# install tigervncserver function
# tigervncserver
install_tigervncserver() {
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y install xfce4 xfce4-goodies
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y install libtasn1-bin libtasn1-3-bin
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y install /share/ven/soft/tigervncserver.deb
    cp /share/ven/soft/xstartup ~/.vnc/xstartup
    chmod 755 ~/.vnc/xstartup
    vncserver :1
}

# Change gateway
if [ -n $GATEWAY_IP ]
then
    sudo /share/ven/bin/chNetwork.py $GATEWAY_IP
fi
# sudo /share/ven/bin/update_file.py file "/share/ven/bin/no_internet/source.list" "/etc/apt/sources.list" 

# Use local disk /dev/sda3 save VM. Format /dev/sda3 if not.
output=$(sudo file -sL /dev/sda3)
if echo "$output" | grep -q " ext"
then
    echo "Found ext, /dev/sda3 formatted"
else
    echo "Formatting /dev/sda3 ..."
    sudo mkfs -t ext4 /dev/sda3
fi

# Prepare vagrant box dir.
if [ ! -d "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/boxes" ]; then
    mkdir "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/"
    mkdir "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant"
    chmod 777 "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant"
    mkdir "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/boxes"
    sudo mount users.ncl.sg:/big/public_share/ven/vagrant/boxes /proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/boxes -o "auto,exec,nolock"
fi

# Set vagrant environment variables, so we can run vagrant any where and share box from share directory.
env_vir="VAGRANT_HOME=/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/
VAGRANT_CWD=/proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
VBOX_USER_HOME=/mnt/sda3/VirtualBox/"
export VAGRANT_HOME=/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/
export VAGRANT_CWD=/proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
export VBOX_USER_HOME=/mnt/sda3/VirtualBox/
sudo /share/ven/bin/update_file.py "$env_vir" "/etc/environment"
#update_conf "$env_vir" "/etc/environment"

if [ ! -d "/mnt/sda3" ]; then
    # Mount /dev/sda3 to /mnt/sda3. After os_load, /dev/sda3 has been formatted, but no /mnt/sda3
    sudo mkdir /mnt/sda3
    sudo mount /dev/sda3 /mnt/sda3
    sudo mkdir /mnt/sda3/vm
    sudo chown $OWNER -R /mnt/sda3
    chmod g+rwx -R /mnt/sda3
    echo "/dev/sda3   /mnt/sda3   auto    rw,user,exec    0   0" | sudo tee --append /etc/fstab > /dev/null

fi

# uninstall default virtualbox 5.1
# suspend vagrant first
dpkg -s virtualbox 2>/dev/null | grep -q ^"Status: install ok installed"$
if [ "$?" -eq "0" ]; then
    vagrant status | awk '/running/{print $1}' | xargs -r -d '\n' -n 1 -- vagrant suspend
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y --purge autoremove virtualbox*
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y --purge autoremove virtualbox-dkms

    # stop remaining virtualbox services
    pgrep -f virtualbox > /dev/null 2>&1
    if [ $? -eq 0 ]; then
        pkill -f virtualbox
    fi

    # require up to 10s for virtualbox services to properly shutdown
    echo "waiting for virtualbox services to close..."
    sleep 10s
fi

#Install virtualbox 5.2 from Oracle's repository
dpkg -s virtualbox-5.2 2>/dev/null | grep -q ^"Status: install ok installed"$
if [ "$?" -ne "0" ]; then
    install_virtualbox
fi

#Install vagrant.
dpkg -s vagrant >/dev/null 2>&1
if [ "$?" -ne "0" ]; then
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y install /share/ven/vagrant.deb
fi

# replace tightvncserver with tigervncserver
dpkg -s tightvncserver 2>/dev/null | grep -q ^"Status: install ok installed"$
if [ "$?" -eq "0" ]; then
    vncserver -kill :1
    sudo DEBIAN_FRONTEND=noninteractive apt-get -y --purge remove tightvncserver
    install_tigervncserver
fi


if [ ! -d "/mnt/vncpass" ]; then
    sudo mkdir /mnt/vncpass
    #create syslink and default passwd
    sudo cp /share/ven/soft/passwd.org /mnt/vncpass/passwd
    ln -sf /mnt/vncpass/passwd ./.vnc/passwd
    sudo chown $OWNER -R /mnt/vncpass
    chmod g+rwx -R /mnt/vncpass
    chmod 600 /mnt/vncpass/passwd 

dpkg -s tigervncserver 2>/dev/null | grep -q ^"Status: install ok installed"$
if [ "$?" -ne "0" ]; then
    install_tigervncserver
fi
  
fi

dpkg -s virtualbox-5.2 vagrant >/dev/null 2>&1
if [ "$?" -ne "0" ]; then
    exit 1
fi

# Setup ssh config, user can directly run 'ssh vm_name' to login VM.
# vagrant ssh-config > /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/ssh.config

# Start up VMs by vangrant
vagrant up  
if [ $? -ne 0 ]
then
    exit 1
fi

vagrant ssh-config > /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/ssh.config


#lines=`cat "/proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/ssh.config"`

sudo /share/ven/bin/update_file.py file "/proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/ssh.config" "/etc/ssh/ssh_config"
#update_conf "$lines" "/etc/ssh/ssh_config"
# Delete all creator_uid vagrant created to let any user can run vagrant.
#rm -f $(find /proj/$TEAM_NAME/$EXP_NAME/ | grep creator_uid)
echo 'Done'
