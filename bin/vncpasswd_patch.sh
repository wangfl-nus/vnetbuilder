if [ ! -d "/mnt/vncpass" ]; then
    sudo mkdir /mnt/vncpass
    sudo cp ~/.vnc/passwd.org /mnt/vncpass/passwd
    sudo chown ntechni3 -R /mnt/vncpass
    chmod g+rwx -R /mnt/vncpass

fi
echo 'Done' 
exit 0
