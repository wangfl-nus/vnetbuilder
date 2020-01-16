#!/bin/bash
if [ ! -d "/mnt/sda3" ]; then
    echo "/mnt/sda3 is not exit".
    sudo mkfs -t ext4 /dev/sda3
    sudo mkdir /mnt/sda3
    sudo mount /dev/sda3 /mnt/sda3
    sudo mkdir /mnt/sda3/vm
    sudo chown lqun4583 -R /mnt/sda3
    chmod g+rwx -R /mnt/sda3
    echo "/dev/sda3   /mnt/sda3   auto    rw,user,exec    0   0" | sudo tee --append /etc/fstab
    vboxmanage setproperty machinefolder /mnt/sda3/vm
    echo "done!"

else
    echo "/mnt/sda3 exist, exit now."
fi
