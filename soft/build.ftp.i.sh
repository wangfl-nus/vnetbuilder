#!/bin/bash -x

if [ "$#" -ge "1" ]; then
   jsonfile=$1
fi

dpkg -s vsftpd >/dev/null 2>&1
if [ $? != 0 ]; then
   # echo $?
   echo "Start installing vsftpd..."
   sudo apt-get update
   sudo DEBIAN_FRONTEND=noninteractive apt-get -yq install vsftpd
   sudo service vsftpd start
   echo "Completed installing vsftpd."
else
   # echo $?
   echo "vsfptd is already installed!"
fi

# echo "Verify vsftpd server status"
sudo netstat -ant | grep 21 >/dev/null 2>&1
if [ $? != 0 ]; then
  echo "start vsftpd service."
  sudo service vsftpd start
fi

# check and configure vsftpd
vsftpd_cfg_file=/etc/vsftpd.conf
default_vsftpd_cfg_file=/vagrant/default_vsftpd.conf

if [ -f "$vsftpd_cfg_file" ]; then
  # compare with default 
  if ! cmp -s "$vsftpd_cfg_file" "$default_vsftpd_cfg_file"
  then
    echo "overwrite /etc/vsftpd.conf with default vsftpd.conf" 
    sudo cp "$default_vsftpd_cfg_file" "$vsftpd_cfg_file"
  fi
else
  # copy default
  echo "copy default vsftpd.conf to /etc"
  sudo cp "$default_vsftpd_cfg_file" "$vsftpd_cfg_file"
fi

# create vsftpd.chrrot_list
outfile=/etc/vsftpd.chroot_list
if [ ! -f "$outfile" ]; then
  echo "create /etc/vsftp.chroot_list" 
  sudo touch "$outfile"
fi

if [ -f "$jsonfile" ]; then
  # add ftp users
  sudo python /vagrant/addusers.py -u $jsonfile -o $outfile
  sudo rm $jsonfile >/dev/null
fi
