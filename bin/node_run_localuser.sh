#!/bin/bash
if [ "$#" -lt "3" ] || [ "$#" -gt "4" ]
then
    echo "$0 node_name experiment_name team_name gateway_ip (opt)"
    exit 1
fi

NODE_NAME=$1
EXP_NAME=$2
TEAM_NAME=$3
VAR4=$4


# create local user
LOCALUSER="localuser"
# RANDOM_PASSWORD=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
RANDOM_PASSWORD="localuser"

echo "$RANDOM_PASSWORD"
echo ""

# force remove existing user if it exists
if [ $(getent passwd $LOCALUSER) ] ; then
  echo Removing existing localuser if script is rerun
  sudo userdel -rfRZ $LOCALUSER
fi


# localuser has to be included in the same linux group for vagrant up to create the respective mounted folders
echo Creating local user...
echo ""
sudo useradd -m $LOCALUSER
sudo usermod --shell /bin/bash $LOCALUSER
sudo usermod -aG $TEAM_NAME $LOCALUSER
sudo echo "$LOCALUSER  ALL=(ALL:ALL) ALL" | sudo tee --append /etc/sudoers
echo Changing student password...
echo ""
echo "$LOCALUSER:$RANDOM_PASSWORD" | sudo chpasswd

if [ -z $VAR4 ]
then 
	echo "not gateway"
elif printf -- '%s' $VAR4 | egrep -q -- "\." 
then
	echo "gateway present"
	GATEWAY_IP=$VAR4
fi


# Use local disk /dev/sda3 save VM. Format /dev/sda3 if not.
output=$(sudo file -sL /dev/sda3)
if echo "$output" | grep -q " ext"
then
    echo "Found ext, /dev/sda3 formatted"
else
    echo "Formatting /dev/sda3 ..."
    sudo mkfs -t ext4 /dev/sda3
fi



LEAD="### BEGIN NCL ADD CONTENT"
TAIL="### END NCL ADD CONTENT"


# Change gateway
if [ -n $GATEWAY_IP ]
then
    sudo /share/ven/bin/chNetwork.py $GATEWAY_IP
fi
sudo /share/ven/bin/update_file.py file "/share/ven/bin/source.list" "/etc/apt/sources.list" 


# Prepare vagrant box dir.
if [ ! -d "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/boxes" ]; then
    mkdir "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/"
    mkdir "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant"
    chmod 777 "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant"
    mkdir "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/boxes"
    sudo mount users.ncl.sg:/big/public_share/ven/vagrant/boxes /proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/boxes -o "auto,exec,nolock"
fi
# mount vagrant boxes
mountpoint "/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/boxes"
if [ "$?" -eq "1" ]; then
    sudo mount users.ncl.sg:/big/public_share/ven/vagrant/boxes /proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/boxes -o "auto,exec,nolock"
fi


# Set vagrant environment variables, so we can run vagrant any where and share box from share directory.
env_vir="VAGRANT_HOME=/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/
VAGRANT_CWD=/proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
VBOX_USER_HOME=/mnt/sda3/VirtualBox/
RANDOM_PASSWORD=$RANDOM_PASSWORD"
export VAGRANT_HOME=/proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/
export VAGRANT_CWD=/proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/
export VBOX_USER_HOME=/mnt/sda3/VirtualBox/
export RANDOM_PASSWORD=$RANDOM_PASSWORD
sudo /share/ven/bin/update_file.py "$env_vir" "/etc/environment"
#update_conf "$env_vir" "/etc/environment"

if [ ! -d "/mnt/sda3" ]; then
    # Mount /dev/sda3 to /mnt/sda3. After os_load, /dev/sda3 has been formatted, but no /mnt/sda3
    echo "y" | sudo mkfs -t ext4 /dev/sda3
    echo "y" | sudo mount /dev/sda3 /mnt/sda3
    sudo mkdir -p /mnt/sda3/vm
    sudo chown $LOCALUSER -R /mnt/sda3
    sudo chmod g+rwx -R /mnt/sda3
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


echo "$RANDOM_PASSWORD" | sudo su - $LOCALUSER <<EOF
echo "INSTALL vb"
#Install virtualbox 5.2 fron share folder
if [ $(dpkg-query -W -f='${Status}' virtualbox-5.2 2>/dev/null | grep -c "ok installed") -eq 0 ];
then
  echo Installing virtualbox...
  echo "$RANDOM_PASSWORD" | sudo -S DEBIAN_FRONTEND=noninteractive dpkg -i /share/ven/soft/virtualbox-5.2.deb
  echo "$RANDOM_PASSWORD" | sudo  DEBIAN_FRONTEND=noninteractive apt-get -yq install
  vboxmanage setproperty machinefolder /mnt/sda3/vm
fi
echo "INSTALL vagrant"
#Install vagrant.
#echo $(dpkg -s vagrant 2>/dev/null | grep -c "ok installed")
echo $(dpkg -s vagrant 2>/dev/null |grep -c "ok installed")
if [ $(dkpg -s vagrant 2>/dev/null |grep -c "ok installed") -eq "0" ]; then
    echo "installing vagrant"
    echo $(dpkg -s vagrant 2>/dev/null |grep -c "ok installed") 
    echo "$RANDOM_PASSWORD" | sudo apt-get update
    # echo "$RANDOM_PASSWORD" | sudo DEBIAN_FRONTEND=noninteractive apt-get -y upgrade
    echo "$RANDOM_PASSWORD" | sudo -S DEBIAN_FRONTEND=noninteractive dpkg -i /share/ven/vagrant.deb
    echo "$RANDOM_PASSWORD" | sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install
fi

echo Changing permission for project folder to allow $LOCALUSER to create the mounted vagrant folders...
echo \"$RANDOM_PASSWORD\" | sudo chmod 775 /proj/$TEAM_NAME/$EXP_NAME
echo ""

#echo Changing permission for vagrant files...
echo "$RANDOM_PASSWORD" | sudo chown $LOCALUSER /proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/insecure_private_key
echo "$RANDOM_PASSWORD" | sudo chown -R $LOCALUSER /proj/$TEAM_NAME/$EXP_NAME/vnetwork/vagrant/data
echo "$RANDOM_PASSWORD" | sudo chown -R $LOCALUSER /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/.vagrant
echo ""

echo "INSTALL vnc"
# replace tightvncserver with tigervncserver
dpkg -s tightvncserver 2>/dev/null | grep -q ^"Status: install ok installed"$
if [ "$?" -eq "0" ]; then
    pkill vnc
    echo "$RANDOM_PASSWORD" | sudo DEBIAN_FRONTEND=noninteractive apt-get -y --purge remove tightvncserver
fi

dpkg -s tigervncserver 2>/dev/null | grep -q ^"Status: install ok installed"$
if [ "$?" -ne "0" ]; then
    echo "$RANDOM_PASSWORD" | sudo -S  apt-get -y install xfce4 xfce4-goodies
    echo "$RANDOM_PASSWORD" | sudo apt-get -y install libtasn1-bin libtasn1-3-bin
    echo "$RANDOM_PASSWORD" | sudo apt-get -y install /share/ven/soft/tigervncserver.deb
fi

echo Configuring vnc password directories...
echo "$RANDOM_PASSWORD" | sudo mkdir -p /mnt/vncpass
mkdir -p /home/$LOCALUSER/.vnc
chown -R $LOCALUSER:$LOCALUSER /home/$LOCALUSER/.vnc
touch ~/.vnc/passwd
   
#create syslink and default passwd
echo "$RANDOM_PASSWORD" | sudo cp /share/ven/soft/passwd.org /mnt/vncpass/passwd
ln -sf /mnt/vncpass/passwd ~/.vnc/passwd
echo "$RANDOM_PASSWORD" | sudo chown $LOCALUSER -R /mnt/vncpass
chmod g+rwx -R /mnt/vncpass
chmod 600 /mnt/vncpass/passwd

export var1=$(dpkg -s virtualbox-5.2 2>/dev/null | grep -c "ok installed")
export var2=$(dpkg -s vagrant 2>/dev/null |grep -c "ok installed")
echo $var1
echo $var2
echo $($var1+$var2)
dpkg -s virtualbox-5.2 vagrant >/dev/null 2>&1
echo $?
if [ $var1 -ne "1" ] || [ $var2 -ne "1" ]; then
    echo "EXIT before vagrant setup"
    exit 1
fi

echo "VAGRANT status"
# vagrant status
# if [ "$?" -ne "0" ]
# then
#    exit 1
# fi

# Setup ssh config, user can directly run 'ssh vm_name' to login VM.
vagrant ssh-config > /proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/ssh.config

echo Starting vnc server...
cp /share/ven/soft/xstartup ~/.vnc/xstartup
chmod 755 ~/.vnc/xstartup
vncserver :1
echo ""

EOF

sudo /share/ven/bin/update_file.py file "/proj/$TEAM_NAME/$EXP_NAME/$NODE_NAME/ssh.config" "/etc/ssh/ssh_config"
echo 'Done'
