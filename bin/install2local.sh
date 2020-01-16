#!/bin/bash -x
# prepare local run shell script to change the network for every node.
# Can run once after experiment.
if [ "$#" -ne "1" ]
then
    echo "$0 gateway_ip "
    exit 1
fi

GATEWAY_IP=$1

SCRIPT="/share/ven/bin/chNetwork.py"
# Change gateway now
sudo $SCRIPT $GATEWAY_IP
# Copy to local disk, for there is no share directory when crontab is running.
DEST_DIR="/var/ncl/bin/"
DEST_SCRIPT=$DEST_DIR"chNetwork.py"
test -d "$DEST_DIR" || sudo mkdir -p "$DEST_DIR" && sudo cp $SCRIPT "$DEST_SCRIPT"

update_conf(){
    content=$1
    conf_file=$2
    content_sed=$3
    LEAD="### BEGIN NCL ADD CONTENT"
    TAIL="### END NCL ADD CONTENT"
    if grep -Fxq "$LEAD" $conf_file
    then
        # If exported before, replace the contend.
        #output=$(sudo sed -n "/$LEAD/{p;:a;N;/$TAIL/!ba;s/.*\n/$content\n/};p" $conf_file)
        output=$(sudo sed -n "/$LEAD/{p;:a;N;/$TAIL/!ba;s,.*\n,$content_sed\n,};p" $conf_file)
        echo "$output" | sudo tee $conf_file > /dev/null
    else
        # Append the ssh.config if not export before.
        echo "$LEAD" | sudo tee --append $conf_file > /dev/null
        echo -e "$content"  | sudo tee --append $conf_file > /dev/null
        echo "$TAIL" | sudo tee --append $conf_file > /dev/null
    fi
}
#CRONTAB_CMD="@reboot root /usr/bin/python $DEST_SCRIPT $GATEWAY_IP > /tmp/chNetwork.log 2>&1 &"
#escape & for sed
CRONTAB_CMD="@reboot root /usr/bin/python $DEST_SCRIPT $GATEWAY_IP > /tmp/chNetwork.log 2>&1 &"
CRONTAB_CMD_SED="@reboot root /usr/bin/python $DEST_SCRIPT $GATEWAY_IP > /tmp/chNetwork.log 2>\&1 \&"
update_conf "$CRONTAB_CMD" "/etc/crontab" "$CRONTAB_CMD_SED"
