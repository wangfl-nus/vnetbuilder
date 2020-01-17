#!/usr/bin/env python
'''The program handle network definition json file and produce NSfile for
deter platform, vagrant file for VMs, ansible inventory/playbook for
installing software, runcmd for up VMs and configure files.'''
import os
import sys
import subprocess
import helpfunc
import stat
from datetime
import getpass

def log_env():
    pyuser = getpass.getuser()
    workingdir = os.getcwd()
    filepath = os.path.realpath(__file__)
    st = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    env_info = "Time: %s,  User: [%s], Working Dir: [%s], FilePath: [%s]" % (st, pyuser, workingdir, filepath)
    return env_info

def log(message):
    env_info = log_env()
    msg = "In function: [%s]" %(message)
    print env_info
    print msg
    with open('netdefdebug.log', 'a+') as f:
        f.write(env_info + "\n")
        f.write(msg + "\n")

DEFAULT_PASSWORD = "Passw0rd"

# outer_dateway, internal_gateway,
BEGIN_TEMPLATE = '''# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box_check_update = false
  config.vm.synced_folder "/share/ven/esys", "/share/ven/esys", create: true
  config.vm.synced_folder "%s/esys", "%s/esys", create: true,
    mount_options: ['rw', 'exec']
'''

END_TEMPLATE = '''end
'''
FORWARD_CMD = r'''update_conf "net.ipv4.ip_forward=1\n" "/etc/sysctl.conf"
sudo sysctl -p /etc/sysctl.conf
'''
SCRIPT_TEMPLATE_BEG = '''    $script = <<SCRIPT
'''
SCRIPT_TEMPLATE_ROUTE = '''sudo ip route delete default
sudo ip route add default via %s
'''
SCRIPT_TEMPLATE_SHELL = r'''update_conf(){
    content=$1
    conf_file=$2
    LEAD="### BEGIN NCL ADD CONTENT"
    TAIL="### END NCL ADD CONTENT"
    if grep -Fxq "$LEAD" $conf_file
    then
        # If exported before, replace the contend.
        output=$(sudo sed -n "/$LEAD/{p;:a;N;/$TAIL/!ba;s/.*\n/$content\n/};p" $conf_file)
        echo "$output" | sudo tee $conf_file > /dev/null
    else
        # Append the ssh.config if not export before.
        echo "$LEAD" | sudo tee --append $conf_file > /dev/null
        echo -e "$content"  | sudo tee --append $conf_file > /dev/null
        echo "$TAIL" | sudo tee --append $conf_file > /dev/null
    fi
}
sudo hostname %s
sudo bash -c "echo %s > /etc/hostname"
update_conf "127.0.1.1 %s" "/etc/hosts"
sudo ln -sf /usr/share/zoneinfo/Asia/Singapore /etc/localtime
sudo dpkg-reconfigure --frontend noninteractive tzdata
'''
SCRIPT_TEMPLATE_END = '''SCRIPT
'''
# Donot change password,it will cause error after changing.
SCRIPT_WIN_TEMPLATE_END = '''route -p change 0.0.0.0 mask 0.0.0.0 %s
SCRIPT
'''

# vm_name, vm_os
VM_TEMPLATE_BEG = '''  config.vm.define "{0}" do |node|
    node.vm.box = "{1}"
'''
VM_TEMPLATE_END = '''    node.vm.provision "shell", path: "%s"
  end
'''
VM_WIN_TEMPLATE_END = '''  end
'''
# name, ip
NET_PRIVATE_TEMPLATE = '''    node.vm.network "private_network", ip: "%s"\n'''
NET_VB_TEMPLATE = '''    node.vm.network "private_network", ip: "%s", virtualbox__intnet:"%s"\n'''
#name, ip, bridge.interface
NET_PUBLIC_TEMPLATE = \
    '''    node.vm.network "public_network", ip: "%s", bridge:"%s"\n'''

# {"NetType": "internal","IP": "172.16.1.2", "NAT": [{'nataddr' : "172.16.3.2", 'natport'=80, 'serveraddr': '171.16.4.1', 'serverport':'80'}]}
# {"NetType": "bridge","IP":"172.16.20.10",  "NAT": []},
# sudo iptables -t nat -A POSTROUTING -o eth3 -j MASQUERADE
def build_net(exp, node, net_conf):
    '''The func output net conf part of vm conf of vagrant config file based
    on net_conf'''
    if not net_conf.has_key('NetType'):
        return ''
    if net_conf["NetType"] == "internal":
        return NET_PRIVATE_TEMPLATE % (net_conf['IP'])
    elif net_conf["NetType"] == "bridge":
        route_table = helpfunc.get_host_routertable(node+'.'+exp)
        if route_table == '':
            print "Error:get router table from [%s]:[%s]" %(node+'.'+exp, route_table)
        
        interface = helpfunc.get_interface_by_ip(
            net_conf['IP'],
            route_table)
        if interface == '':
            print "Error: get IP[%s]'s interface from route_table[%s]"\
                % (net_conf['IP'], route_table)
        return NET_PUBLIC_TEMPLATE % (net_conf['IP'], interface)
    else:
        print "Info: Use virtualbox intrernal named net[%s]"%str(net_conf)
        return NET_VB_TEMPLATE % (net_conf['IP'], net_conf['NetType'])
'''            {
                "Name": "ubuntu16n1",
                "OS": "ubuntuboxname",
                "Nets":[{
                    "NetType": "internal",
                    "IP": "172.16.1.3"
                    }
                ],
                "Roles":["PlaybookRoleName"]
            },
'''
PORTFORWARD_TEMPLATE = '    node.vm.network "forwarded_port", guest: {}, host:{}\n'
def build_vm_portforward(pf_conf):
    '''The func output portforward part of vagrant config file based on pf_conf.
    node.vm.network "forwarded_port", guest: 8000, host:8000
    https://www.vagrantup.com/docs/networking/forwarded_ports.html
    {"guest":8000}'''
    guest_port = pf_conf['guest']
    host_port = guest_port
    if pf_conf.has_key('host'):
        host_port = pf_conf['host']
    return PORTFORWARD_TEMPLATE.format(guest_port, host_port)

def build_vm(exp, node, vm_conf):
    '''The func output vm part of vagrant config file based on vm_conf'''
    vm_name = vm_conf['Name']
    '''
    if vm_conf.has_key('Password'):
        password = vm_conf['Password']
    else:
        password = DEFAULT_PASSWORD '''
    out_str = VM_TEMPLATE_BEG.format(vm_conf["Name"], vm_conf["OS"])

    if vm_conf.has_key('Nets'):
        for net_conf in vm_conf['Nets']:
            out_str += build_net(exp, node, net_conf)
    if vm_conf.has_key('portforward'):
        out_str += build_vm_portforward(vm_conf['portforward'])
    if vm_conf['OS'].find('win') != -1:
        # windows system.
        out_str += VM_WIN_TEMPLATE_END
    else:
        out_str += VM_TEMPLATE_END % ("%s.conf.sh"%vm_name)
    return out_str
def guess_gateway_ip(vm_conf):
    '''The func guess gateway ip.'''
    gateway = ''
    # If not define gateway, guess it.
    if vm_conf.has_key('Nets'):
        # if there are bridge type, guess based on it.
        for net_conf in vm_conf['Nets']:
            if not net_conf.has_key('NetType'):
                continue
            if net_conf['NetType'] == 'bridge':
                gateway = helpfunc.get_gateway_ip_by_first_ip(net_conf['IP'])
        # or based on IP which is not .100
        if gateway == '':
            for net_conf in vm_conf['Nets']:
                if not net_conf.has_key('IP'):
                    continue
                if not net_conf['IP'].endswith('.100'):
                    gateway = helpfunc.get_gateway_ip_by_first_ip(net_conf['IP'])
        # or guess based on the first IP.
        if gateway == '':
            print "Warn in guess VM[%s]'s gateway IP. All right if using management interface." % str(vm_conf['Name'])
    return gateway
NAT_MASQUERADE_NAT = '''INTERFACE="$(ip route show | grep default | awk '{print $5}')"
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
'''

NAT_MASQUERADE = '''INTERFACE="$(ip route show | grep %s | awk '{print $3}')"
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
'''
NAT_CMD = '''sudo iptables -t nat %s
'''
IPSAVE_CMD = '''sudo DEBIAN_FRONTEND=noninteractive apt-get -y install iptables-persistent
sudo dpkg-reconfigure -p critical iptables-persistent
'''
def build_vm_conf_sh(vm_conf):
    '''The func build configure VM shell script.
    sudo iptables -t nat -A POSTROUTING -o eth3 -j MASQUERADE
    iptables -t nat -A PREROUTING -p tcp -d 10.10.20.99 --dport 80 -j DNAT --to-destination 10.10.14.2
'''
    vm_name = vm_conf['Name']
    gateway = ''
    if vm_conf.has_key('Gateway'):
        gateway = vm_conf['Gateway']
    else:
        gateway = guess_gateway_ip(vm_conf)
    forward = vm_conf.has_key('Forward')
    out_str = ''
    if vm_conf['OS'].find('win') != -1:
        # windows system.
        out_str += ""
    else:
        if gateway != '':
            out_str += SCRIPT_TEMPLATE_ROUTE % gateway
        out_str += SCRIPT_TEMPLATE_SHELL % (vm_name, vm_name, vm_name)
        if forward:
            out_str += FORWARD_CMD
    if vm_conf.has_key('run'):
        for line in vm_conf['run']:
            output += line
            output += '\n'
    if vm_conf.has_key('Nets'):
        for net_conf in vm_conf['Nets']:
            if net_conf.has_key('NAT'):
                if not net_conf.has_key('IP'):
                    # if there is no IP definition but NAT, NAT to management interface 
                    # which is default route to .
                    out_str += NAT_MASQUERADE_NAT
                else:
                    out_str += NAT_MASQUERADE % net_conf['IP']
                for nat_cmd in net_conf['NAT']:
                    if nat_cmd == '':
                        continue
                    out_str += NAT_CMD % nat_cmd
                out_str += IPSAVE_CMD
    return out_str

def build_node(exp, node_conf, exp_folder):
    '''The func output whole vagrant config file based on node_conf'''
    node_name = node_conf['Name']
    out_str = BEGIN_TEMPLATE % (exp_folder, exp_folder)
    for vm_conf in node_conf['VMs']:
        out_str += build_vm(exp, node_name, vm_conf)
    out_str += END_TEMPLATE
    return out_str
def build_ansible_roles(name, roles_conf):
    '''The func output part of ansible playbook to run roles(roles_conf) on
    host(name). Such as, roles_conf:
    {
        "Name":"n1",
        "Roles":["PlaybookRoleName",
            "PlaybookRoleName",
            "PlaybookRoleName"
        ], or
            {"Name": "DBServern2",
                "OS": "bento/ubuntu-16.10",
                "Nets":[{"NetType": "internal","IP": "172.16.2.1"}],
                "Roles":["mysql, mysql_db: [{name: bbs}, {name: wp}], mysql_users:
                [{name: bbs, pass: Passw0rd, priv: '*.*:ALL'},
                {name: wp, pass: Passw0rd, priv: '*.*:ALL'}]"]
    '''
    tmp_playbook_roles1 = '''- name: Install roles on {0}
  hosts: {0}
  become: true
  roles:
'''
    tmp_playbook_roles2 = "    - {role: %s }\n"
    if roles_conf == {}:
        return ''
    if name == '':
        return ''
    out_str = tmp_playbook_roles1.format(name)
    for role_conf in roles_conf:
        out_str += tmp_playbook_roles2 % role_conf
    return out_str

def build_exp_ansible_inventory(exp_conf):
    ''' The func output ansible inventory string based on exp_conf. '''
    exp_full_name = exp_conf['ExperimentDomainName']
    names = exp_full_name.split('.')
    exp_name = names[0]
    team_name = names[1]
    # Build inventory
    out_str = '[nodes]\n'
    for node_conf in exp_conf['Nodes']:
        node_name = node_conf["Name"]
        out_str += node_name + '.' + exp_full_name + '\n'
    out_str += '\n'
    for node_conf in exp_conf['Nodes']:
        node_name = node_conf["Name"]
        out_str += '[VM%s]\n' % node_name
        if not node_conf.has_key('VMs'):
            continue
        for vm_conf in node_conf['VMs']:
            out_str += vm_conf['Name'] + '\n'
        out_str += '\n'
        out_str += '[VM%s:vars]\n' % node_name
        out_str += """ansible_ssh_common_args= '-F /proj/{2}/{1}/{0}/ssh.config -o ProxyCommand="ssh -W %h:%p -q {0}.{1}.{2}.ncl.sg"'""".format(node_name, exp_name, team_name)
        out_str += '\n'
        out_str += '\n'
    return out_str

def build_ansible_playbook_roles(exp_conf):
    '''The func output ansible playbook about building roles on nodes and VMs.'''
    out_str = ''
    # Build the roles for nodes and VMs.
    for node_conf in exp_conf['Nodes']:
        node_full_name = node_conf["Name"] + '.' + exp_conf['ExperimentDomainName']
        if node_conf.has_key('Roles'):
            out_str += build_ansible_roles(node_full_name, node_conf['Roles'])
        if (node_conf.has_key('VMs')) and (node_conf['VMs'] != {}):
            for vm_conf in node_conf['VMs']:
                if vm_conf.has_key('Roles'):
                    out_str += build_ansible_roles(vm_conf['Name'], vm_conf['Roles'])
    return out_str

TMP_PLAYBOOK1 = '''- name: Install vagrant and virtualbox
  hosts: %s
  tasks:
    - name: install virtualbox
      apt: name=virtualbox
      become: true
    - name: install vagrant via builder deb package
      apt: deb="/share/ven/vagrant.deb"
      become: true
    - name: check if vagrant is installed
      shell: dpkg-query -s vagrant | grep 'install ok installed'
      register: deb_check
      failed_when: deb_check.rc != 0
'''
    # Run tasks on specific node.
TMP_PLAYBOOK2 = '''- name: Run vagrant up on {0}
  hosts: {0}.{1}.{2}.ncl.sg
  tasks:
    - name: Make local disk /dev/sda3 and work as virtualbox home dir.
      script: /share/ven/bin/mkfs.sda3.sh
      become: true
    - name: Set environment variable VAGRANT_CWD / VAGRANT_HOME to let user run vagrant anywhere / share same boxes.
      script: /share/ven/bin/node_conf.py env "/proj/{2}/{1}/{0}/"
      become: true
    - name: start up vagrant on {0}
      command: vagrant up  chdir=/proj/{2}/{1}/{0}/
    - name: Cat ssh config out
      shell: vagrant ssh-config > ssh.config
      args:
        chdir: /proj/{2}/{1}/{0}/
    - name: Setup ssh config on node
      shell: cat ssh.config | tee --append /etc/ssh/ssh_config
      become: true
      args:
        chdir: /proj/{2}/{1}/{0}/
'''
TMP_PLAYBOOK3 = '''- name: Configure vagrant accessability and dir
  hosts: {0}
  become: true
  tasks:
    - name: Remove vagrant creator_uid in case vagrant creator-checking.
      shell: rm -f $(find /proj/{2}/{1}/ | grep creator_uid)
    - name: Let group have rw to dir, so group can run vagrant under the dir.
      shell: chmod g+rw -R /proj/{2}/{1}
'''
def build_ansible_palybook_up_vm(exp_conf):
    '''The func output ansible playbook string to install vagrant/vbox, and
    vagrant up and configure.'''
    # Install vagrant/virtualbox on every node with VM
    # Get the name string of all nodes with VM.
    node_names_vm = ''
    exp_full_name = exp_conf['ExperimentDomainName']
    for node_conf in exp_conf['Nodes']:
        node_full_name = node_conf["Name"] + '.' + exp_full_name
        if (node_conf.has_key('VMs')) and (node_conf['VMs'] != {}):
            if node_names_vm == '':
                node_names_vm += node_full_name
            else:
                node_names_vm += ', ' + node_full_name
    out_str = TMP_PLAYBOOK1 % node_names_vm
    # Run vagrant up on every node with VM.
    names = exp_full_name.split('.')
    exp_name = names[0]
    team_name = names[1]
    for node_conf in exp_conf['Nodes']:
        node_full_name = node_conf["Name"] + '.' + exp_name
        node_name = node_conf["Name"]
        if node_conf.has_key('VMs') and (node_conf['VMs'] != {}):
            out_str += TMP_PLAYBOOK2.format(node_name, exp_name, team_name)
    # Configure dir, let group access vagrantfile.
    out_str += TMP_PLAYBOOK3.format(node_names_vm, exp_name, team_name)

    return out_str
FILENAME_UP_VM = 'up_vm.yml'
FILENAME_BUILD_APP = 'build_app.yml'
def build_exp_ansible(exp_conf, exp_home_dir):
    '''The func build ansible file.'''
    log("build_exp_ansible")
    inventory_file_name = os.path.join(exp_home_dir, "inventory")
    with open(inventory_file_name, "w") as afile:
        afile.write(build_exp_ansible_inventory(exp_conf))
    '''
    playbook_file_name = os.path.join(exp_home_dir, FILENAME_UP_VM)
    with open(playbook_file_name, "w") as afile:
        afile.write(build_ansible_palybook_up_vm(exp_conf))
    playbook_file_install_app = os.path.join(exp_home_dir, FILENAME_BUILD_APP)
    with open(playbook_file_install_app, "w") as afile:
        afile.write(build_ansible_playbook_roles(exp_conf))
        '''
def build_exp_vf(exp_conf, exp_home_dir):
    '''The func read experiment config file and create needed vagrant file
    for every nodes under home_dir.
    Create experiment home dir and create node home dir, create Vagrant file
    under node home dir.'''
    log("build_exp_vf")
    exp_name = exp_conf['ExperimentDomainName']
    # Create vagrant for every node.
    for node_conf in exp_conf['Nodes']:
        if (node_conf.has_key('VMs')) and (node_conf['VMs'] != {}):
            node_name = node_conf["Name"]
            node_home_dir = os.path.join(exp_home_dir, node_name)
            if not os.path.exists(node_home_dir):
                print "Create node home directory[%s]" % node_home_dir
                log("build_exp_vf makedirs")
                os.makedirs(node_home_dir)
            else:
                print "Node home directory already exists [%s]" % node_home_dir
            node_vagrant_filename = os.path.join(node_home_dir, "Vagrantfile")
            with open(node_vagrant_filename, "w") as node_vagrant_file:
                node_vagrant_file.write(build_node(exp_name, node_conf, exp_home_dir))
            for vm_conf in node_conf['VMs']:
                vm_conf_filename = os.path.join(node_home_dir, "%s.conf.sh"%vm_conf['Name'])
                with open(vm_conf_filename, "w") as vm_conf_file:
                    vm_conf_file.write(build_vm_conf_sh(vm_conf))
                os.chmod(vm_conf_filename, 0775)

def build_exp_nsfile(exp_conf):
    '''The func produce nsfile for deter.'''
    out_str = '''set ns [new Simulator]
source tb_compat.tcl

# Set node.
'''
    log("build_exp_nsfile")
    gateway = ''
    reserve_list = []
    if exp_conf.has_key('Reserve'):
        reserve_list = exp_conf['Reserve'].split(',')
    rindex = 0
    for node_conf in exp_conf['Nodes']:
        node_name = node_conf["Name"]
        out_str += "set %s [$ns node]\n" % node_name
        if node_conf.has_key('Image'):
            out_str += "tb-set-node-os $%s %s\n" % (node_name, node_conf['image'])
        else:
            out_str += "tb-set-node-os $%s Ubuntu16.04.3-amd64\n" % node_conf["Name"]
        if rindex < len(reserve_list):
            if reserve_list[rindex].strip() == '':
                print "Error: Reserve have null node name[%s]" % exp_conf['Reserve']
            else:
                out_str += "tb-fix-node $%s %s\n" % (node_name, reserve_list[rindex].strip())
                rindex += 1
        if node_conf.has_key('Type'):
            if node_conf['Type'] == 'Gateway':
                gateway = node_name
    if not exp_conf.has_key('LANs'):
        return out_str
    lan_num = 0
    out_str += '\n# Set LAN.\n'
    for lan_conf in exp_conf['LANs']:
        subnet = lan_conf['Subnet']
        lan_str = ''
        lan_name = 'lan'+str(lan_num)
        lan_num += 1
        for node_ip_conf in lan_conf['LAN']:
            if lan_str == '':
                lan_str += '$' + node_ip_conf[0]
            else:
                lan_str += ' $' + node_ip_conf[0]
            node_ip = subnet + node_ip_conf[1]
        out_str += 'set %s [$ns make-lan "%s" 10Gb 0ms]\n' % (lan_name, lan_str)

    out_str += '\n# Set node ip.\n'
    gateway_ip = ''
    lan_num = 0
    for lan_conf in exp_conf['LANs']:
        subnet = lan_conf['Subnet']
        lan_str = ''
        lan_name = 'lan'+str(lan_num)
        lan_num += 1
        for node_ip_conf in lan_conf['LAN']:
            node_name = node_ip_conf[0]
            if lan_str == '':
                lan_str += '$' + node_name
            else:
                lan_str += ' $' + node_name
            node_ip = subnet + node_ip_conf[1]
            if node_ip != '':
                out_str += "tb-set-ip-lan $%s $%s %s\n"% (node_name, lan_name, node_ip)
            if gateway == node_name:
                gateway_ip = node_ip
    if gateway_ip != '':
        out_str += '\n# Set route and adjust configure.\n$ns rtproto Static\n'
        for node_conf in exp_conf['Nodes']:
            node_name = node_conf["Name"]
            out_str += 'tb-set-node-startcmd $%s '\
                '"/share/ven/bin/install2local.sh %s > '\
                '/tmp/install2local.log 2>&1"\n' % (node_name, gateway_ip)

    out_str += '\n# Go!\n$ns run\n'
    return out_str
INSTALL_PLAYBOOK_LIST = ['install.web', 'install.db', 'install.email']
INSTALL_CMD_LIST = ['install.splunk', 'install.snort', 'install.dns']
CMD_PLAYBOOK = 'ansible-playbook -i inventory /share/ven/soft/%s.yml --extra-vars "%s"'
CMD_SHELL_NODE = '/share/ven/soft/%s.sh %s'
CMD_SHELL_VM = '/share/ven/soft/%s.sh %s %s %s %s %s'
def build_install_node(node_conf, exp_name, team_name):
    '''The func handle node and VM's 'install', output shell to install software.'''
    log("build_install_node")
    output = ''
    builder_cmd = ''
    if node_conf.has_key('install'):
        for line in node_conf['install']:
            install = line.split(' ')[0]
            index = line.find(' ')
            para = ''
            if index != -1:
                para = line[index+1:]
            if install in INSTALL_PLAYBOOK_LIST:
                nfname = '%s.%s.%s.ncl.sg'%(node_conf['Name'], exp_name, team_name)
                builder_cmd += CMD_PLAYBOOK % (install, "vhosts=%s"%nfname)
                builder_cmd += '\n'
            elif install in INSTALL_CMD_LIST:
                output += (CMD_SHELL_NODE % (install, para)).strip()
                output += '\n'
            else:
                print "Error: Cannot find the install command [%s] on node [%s]"\
                    % (line, node_conf['Name'])
    if node_conf.has_key('run'):
        for line in node_conf['run']:
            output += line
            output += '\n'
    if node_conf.has_key('VMs'):
        for vm_conf in node_conf['VMs']:
            if vm_conf.has_key('install'):
                for line in vm_conf['install']:
                    install = line.split(' ')[0]
                    index = line.find(' ')
                    para = ''
                    if index != -1:
                        para = line[index + 1 : ]
                    if install in INSTALL_PLAYBOOK_LIST:
                        builder_cmd += CMD_PLAYBOOK % (install, "vhosts=%s" % vm_conf['Name'])
                        builder_cmd += '\n'
                    elif install in INSTALL_CMD_LIST:
                        output += (CMD_SHELL_VM % (install, vm_conf['Name'],node_conf['Name'],\
                                                  exp_name, team_name, para)).strip()
                        if install.endswith('dns'):
                            ip = vm_conf['Nets'][0]['IP']
                            domain = "%s.%s.ncl.sg" % (exp_name, team_name)
                            output += " " + ip
                            builder_cmd += CMD_PLAYBOOK % ("install.dns.client", "ip=%s domain=%s" % (ip, domain))
                            builder_cmd += "\n"
                        output += '\n'
                    else:
                        print "Error: Cannot find the install command [%s] on VM [%s]"\
                            % (line, vm_conf['Name'])
    return output, builder_cmd

def get_exp_conf(exp_conf_filename):
    '''Read experiment configure file to exp_conf'''
    import json
    with open(exp_conf_filename, "r") as afile:
        exp_conf_str = afile.read()
    return json.loads(exp_conf_str)
def create_exp_dir(exp_home_dir):
    '''The func create exp dir.'''
    log("create_exp_dir")
    if not os.path.exists(exp_home_dir):
        print "Create experiment home directory[%s]" % exp_home_dir
        log("create_exp_dir makedirs")
        os.makedirs(exp_home_dir)
    else:
        print "Experiment home directory already exists [%s]" % exp_home_dir
def build_exp(exp_conf_file, home_dir):
    '''The func read experiment config file and create needed vagrant file
    for every nodes under home_dir.
    Create experiment home dir and create node home dir, create Vagrant file
    under node home dir.'''
    log("build_exp")
    exp_conf = get_exp_conf(exp_conf_file)
    exp_name = exp_conf['ExperimentDomainName'].split('.')[0]
    exp_home_dir = os.path.join(home_dir, exp_name)
    create_exp_dir(exp_home_dir)

    # Create vagrantfile for every node.
    build_exp_vf(exp_conf, exp_home_dir)
    # Create the ansible inventory file and playbook.
    build_exp_ansible(exp_conf, exp_home_dir)
    # Run the ansible playbook to up vagrant.
    inventory_file_name = os.path.join(exp_home_dir, "inventory")
    playbook_file_name = os.path.join(exp_home_dir, FILENAME_UP_VM)
    subprocess.check_output("ansible-playbook -i %s -vvv %s" % \
        (inventory_file_name, playbook_file_name), shell=True)

def build_host_file(exp_conf):
    ''' create hostname - ip pair for connectivity checking and dns setup'''
    log("build_host_file")
    out_str = ''
    for node_conf in exp_conf['Nodes']:
        node_name = node_conf["Name"]
        if node_conf.has_key('VMs'):
            for vm_conf in node_conf['VMs']:
                vm_name = vm_conf['Name']
                if vm_conf.has_key('Nets'):
                    for net_conf in vm_conf['Nets']:
                        if net_conf.has_key('IP'):
                            out_str += '%s,%s\n' % (vm_name, net_conf["IP"])
    if exp_conf.has_key('LANs'):
        for lan_conf in exp_conf['LANs']:
            subnet = lan_conf['Subnet']
            for node_conf in lan_conf['LAN']:
               out_str += node_conf[0] + "," + subnet + node_conf[1] + "\n"
    return out_str


# For test funcs.
def test_get_interface_by_ip(ip1, routert):
    '''This is a mock func.'''
    return 'ethtest1'
def get_host_routertable(node_name):
    '''This is a mock func.'''
    return ''
def get_routervm(anode_name, exp_conf):
    '''The func find anode 's VM with forward.'''
    for tnode_conf in exp_conf['Nodes']:
        if anode_name != tnode_conf["Name"]:
            continue
        if not tnode_conf.has_key('VMs'):
            continue
        for tvm_conf in tnode_conf['VMs']:
            if not tvm_conf.has_key('Forward'):
                continue
            return tvm_conf
    return {}

def produce_cmd4gateway(exp_conf):
    ''' Find the gateway and produce cmds for gateway.'''
    gateway_ip = ''
    out_str = ''
    gateway_node = ''
    for node_conf in exp_conf['Nodes']:
        # If it is the gateway, need add route to vm subnet.
        if (not node_conf.has_key('Type')) or (node_conf['Type'] != 'Gateway'):
            continue
        if not exp_conf.has_key('LANs'):
            print 'Error:no LANs defination, can not find gateway.'
            continue
        # Find Gateway, produce cmd for gateway.
        gateway_node = node_conf["Name"]
        # every node connect with gateway, if node have VM work as router
        #with forward, get other network's subnet, add subnet router via the
        #router vm 's same subnet IP.
        for lan_conf in exp_conf['LANs']:
            found_gateway = False
            for anode in lan_conf['LAN']:
                if anode[0] == gateway_node:
                    found_gateway = True
                    if gateway_ip == '':
                        # Use the first gateway_ip if there two subnet.
                        #TODO, there may have different subnet.
                        gateway_ip = lan_conf['Subnet'] + anode[1]
                        out_str += 'sudo /share/ven/bin/chNetwork.py %s\n' \
                            % gateway_ip
                    break
            if not found_gateway:
                continue
            for anode in lan_conf['LAN']:
                anode_name = anode[0]
                # find the router VM with forward.
                tvm_conf = get_routervm(anode_name, exp_conf)
                if tvm_conf == {}:
                    continue
                # this vm work as router. get his public ip
                subnet_gateway = ''
                for tvm_net_conf in tvm_conf['Nets']:
                    vm_ip = tvm_net_conf['IP']
                    if not vm_ip.startswith(lan_conf['Subnet']):
                        continue
                    subnet_gateway = vm_ip
                if subnet_gateway == '':
                    continue
                # all other subnet go through vm's subnet_gateway
                for tvm_net_conf in tvm_conf['Nets']:
                    vm_ip = tvm_net_conf['IP']
                    if vm_ip == subnet_gateway:
                        continue
                    # There suppose the subnet is /24. Todo depend other require.
                    subnet = vm_ip[0:vm_ip.rfind('.')]+'.0/24'
                    out_str += 'sudo ip route add %s via %s'%\
                        (subnet, subnet_gateway)
                    out_str += '\n'
    return gateway_ip, gateway_node, out_str

FILENAME_ANSIBLE_LOG = 'ansible.log'
def get_exp_home_dir(exp_conf):
    '''The func get exp home dir.'''
    if os.name == 'nt':
        home_dir = './vagrant'
    else:
        home_dir = '/proj'
    names = exp_conf['ExperimentDomainName'].split('.')
    exp_name = names[0]
    team_name = names[1]
    exp_home_dir = os.path.join(home_dir, team_name, exp_name)
    create_exp_dir(exp_home_dir)
    return exp_home_dir
def test():
    '''Test func.'''
    exp_name = "IS613.teaching.ncl.sg"
    node_name = 'n1'
    net_conf1 = {"NetType": "internal", "IP": "172.16.1.2"}
    assert build_net("test", "node", net_conf1) == \
        '    node.vm.network "private_network", ip: "172.16.1.2"\n'
    net_conf2 = {"NetType": "bridge", "IP":"172.16.20.10"}
    func1 = helpfunc.get_interface_by_ip
    func2 = helpfunc.get_host_routertable
    helpfunc.get_interface_by_ip = test_get_interface_by_ip
    helpfunc.get_host_routertable = get_host_routertable
    assert build_net(exp_name, node_name, net_conf2) == \
        '    node.vm.network "public_network", ip: "172.16.20.10", bridge:"ethtest1"\n'
    assert build_net("test", "node", {}) == \
        ''
    assert build_net("test", "node", {'NAT':[]}) == \
        ''
    vm_conf = {"Name": "win10n1",
               "OS": "win10boxname",
               "portforward":{"guest":8000},
               "Nets":[{"NetType": "internal", "IP": "172.16.1.2"}],
               "Roles":["PlaybookRoleName"]
              }
    assert build_vm_portforward({"guest":8000}) == \
        '    node.vm.network "forwarded_port", guest: 8000, host:8000\n'
    assert build_vm('exp', 'node', vm_conf) == \
        '''  config.vm.define "win10n1" do |node|
    node.vm.box = "win10boxname"
    node.vm.network "private_network", ip: "172.16.1.2"
    node.vm.network "forwarded_port", guest: 8000, host:8000
  end
'''
#    node.vm.provision "shell", path: "win10n1.conf.sh"
    vm_conf = {"Name": "win10n1",
               "OS": "win10boxname",
               "Nets":[{"NetType": "internal", "IP": "172.16.1.2"}],
               "Roles":["PlaybookRoleName"]
              }
    assert build_vm('exp', 'node', vm_conf) == \
        '''  config.vm.define "win10n1" do |node|
    node.vm.box = "win10boxname"
    node.vm.network "private_network", ip: "172.16.1.2"
  end
'''
    vm_conf2 = {"Name": "routern1",
                "OS": "ubuntu/xenial64",
                "Forward": 1,
                "Nets":[{"NetType": "bridge", "IP":"172.16.20.10"},
                        {"NetType": "internal", "IP": "172.16.1.100"}
                       ]
               }
    str2 = r'''  config.vm.define "routern1" do |node|
    node.vm.box = "ubuntu/xenial64"
    node.vm.network "public_network", ip: "172.16.20.10", bridge:"ethtest1"
    node.vm.network "private_network", ip: "172.16.1.100"
    node.vm.provision "shell", path: "routern1.conf.sh"
  end
'''
    #diff = difflib.Differ()
    #from pprint import pprint
    #pprint( list(diff.compare(build_vm(exp_name, node_name, vm_conf2).
    # splitlines(), str2.splitlines())))
    assert build_vm(exp_name, node_name, vm_conf2) == str2

    assert guess_gateway_ip(vm_conf) == '172.16.1.100'
    assert guess_gateway_ip(vm_conf2) == '172.16.20.100'
    vm_conf3 = {"Name": "routern1",
                "OS": "ubuntu/xenial64",
                "Forward": 1,
                "Nets":[{"NetType": "internal", "IP": "172.16.1.100"},
                        {"NetType": "bridge", "IP":"172.16.20.10"}
                       ]
               }
    assert guess_gateway_ip(vm_conf3) == '172.16.20.100'
    
    assert build_vm_conf_sh(vm_conf) == ''
    assert build_vm_conf_sh(vm_conf2) == r'''sudo ip route delete default
sudo ip route add default via 172.16.20.100
update_conf(){
    content=$1
    conf_file=$2
    LEAD="### BEGIN NCL ADD CONTENT"
    TAIL="### END NCL ADD CONTENT"
    if grep -Fxq "$LEAD" $conf_file
    then
        # If exported before, replace the contend.
        output=$(sudo sed -n "/$LEAD/{p;:a;N;/$TAIL/!ba;s/.*\n/$content\n/};p" $conf_file)
        echo "$output" | sudo tee $conf_file > /dev/null
    else
        # Append the ssh.config if not export before.
        echo "$LEAD" | sudo tee --append $conf_file > /dev/null
        echo -e "$content"  | sudo tee --append $conf_file > /dev/null
        echo "$TAIL" | sudo tee --append $conf_file > /dev/null
    fi
}
sudo hostname routern1
sudo bash -c "echo routern1 > /etc/hostname"
update_conf "127.0.1.1 routern1" "/etc/hosts"
sudo ln -sf /usr/share/zoneinfo/Asia/Singapore /etc/localtime
sudo dpkg-reconfigure --frontend noninteractive tzdata
update_conf "net.ipv4.ip_forward=1\n" "/etc/sysctl.conf"
sudo sysctl -p /etc/sysctl.conf
'''
    vm_conf3 = {"Name": "routern1",
                "OS": "ubuntu/xenial64",
                "Forward": 1,
                "Nets":[{"NetType": "bridge", "IP":"172.16.20.10"},
                        {"NetType": "internal", "IP": "172.16.1.100", 'NAT':[]}
                       ]
               }
    assert build_vm_conf_sh(vm_conf3) == r'''sudo ip route delete default
sudo ip route add default via 172.16.20.100
update_conf(){
    content=$1
    conf_file=$2
    LEAD="### BEGIN NCL ADD CONTENT"
    TAIL="### END NCL ADD CONTENT"
    if grep -Fxq "$LEAD" $conf_file
    then
        # If exported before, replace the contend.
        output=$(sudo sed -n "/$LEAD/{p;:a;N;/$TAIL/!ba;s/.*\n/$content\n/};p" $conf_file)
        echo "$output" | sudo tee $conf_file > /dev/null
    else
        # Append the ssh.config if not export before.
        echo "$LEAD" | sudo tee --append $conf_file > /dev/null
        echo -e "$content"  | sudo tee --append $conf_file > /dev/null
        echo "$TAIL" | sudo tee --append $conf_file > /dev/null
    fi
}
sudo hostname routern1
sudo bash -c "echo routern1 > /etc/hostname"
update_conf "127.0.1.1 routern1" "/etc/hosts"
sudo ln -sf /usr/share/zoneinfo/Asia/Singapore /etc/localtime
sudo dpkg-reconfigure --frontend noninteractive tzdata
update_conf "net.ipv4.ip_forward=1\n" "/etc/sysctl.conf"
sudo sysctl -p /etc/sysctl.conf
INTERFACE="$(ip route show | grep 172.16.1.100 | awk '{print $3}')"
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install iptables-persistent
sudo dpkg-reconfigure -p critical iptables-persistent
'''
    vm_conf4 = {"Name": "routern1",
                "OS": "ubuntu/xenial64",
                "Forward": 1,
                "Nets":[{"NetType": "bridge", "IP":"172.16.20.10"},
                        {"NetType": "internal", "IP": "172.16.1.100", 'NAT':["-A PREROUTING -p tcp -d 10.10.20.99 --dport 80 -j DNAT --to-destination 10.10.14.2"]}
                       ]
               }
    assert build_vm_conf_sh(vm_conf4) == r'''sudo ip route delete default
sudo ip route add default via 172.16.20.100
update_conf(){
    content=$1
    conf_file=$2
    LEAD="### BEGIN NCL ADD CONTENT"
    TAIL="### END NCL ADD CONTENT"
    if grep -Fxq "$LEAD" $conf_file
    then
        # If exported before, replace the contend.
        output=$(sudo sed -n "/$LEAD/{p;:a;N;/$TAIL/!ba;s/.*\n/$content\n/};p" $conf_file)
        echo "$output" | sudo tee $conf_file > /dev/null
    else
        # Append the ssh.config if not export before.
        echo "$LEAD" | sudo tee --append $conf_file > /dev/null
        echo -e "$content"  | sudo tee --append $conf_file > /dev/null
        echo "$TAIL" | sudo tee --append $conf_file > /dev/null
    fi
}
sudo hostname routern1
sudo bash -c "echo routern1 > /etc/hostname"
update_conf "127.0.1.1 routern1" "/etc/hosts"
sudo ln -sf /usr/share/zoneinfo/Asia/Singapore /etc/localtime
sudo dpkg-reconfigure --frontend noninteractive tzdata
update_conf "net.ipv4.ip_forward=1\n" "/etc/sysctl.conf"
sudo sysctl -p /etc/sysctl.conf
INTERFACE="$(ip route show | grep 172.16.1.100 | awk '{print $3}')"
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
sudo iptables -t nat -A PREROUTING -p tcp -d 10.10.20.99 --dport 80 -j DNAT --to-destination 10.10.14.2
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install iptables-persistent
sudo dpkg-reconfigure -p critical iptables-persistent
'''
    vm_conf5= {'Name': 'gw2', 'OS': 'bento/ubuntu-16.04', 'Forward': 1,
                      'Nets': [{'IP': '172.16.10.100', 'NetType': 'VN3'},
                               {'IP': '172.16.20.100', 'NetType': 'VN5'},
                               {'NAT':[]}]}
    assert build_vm_conf_sh(vm_conf5) == r'''update_conf(){
    content=$1
    conf_file=$2
    LEAD="### BEGIN NCL ADD CONTENT"
    TAIL="### END NCL ADD CONTENT"
    if grep -Fxq "$LEAD" $conf_file
    then
        # If exported before, replace the contend.
        output=$(sudo sed -n "/$LEAD/{p;:a;N;/$TAIL/!ba;s/.*\n/$content\n/};p" $conf_file)
        echo "$output" | sudo tee $conf_file > /dev/null
    else
        # Append the ssh.config if not export before.
        echo "$LEAD" | sudo tee --append $conf_file > /dev/null
        echo -e "$content"  | sudo tee --append $conf_file > /dev/null
        echo "$TAIL" | sudo tee --append $conf_file > /dev/null
    fi
}
sudo hostname gw2
sudo bash -c "echo gw2 > /etc/hostname"
update_conf "127.0.1.1 gw2" "/etc/hosts"
sudo ln -sf /usr/share/zoneinfo/Asia/Singapore /etc/localtime
sudo dpkg-reconfigure --frontend noninteractive tzdata
update_conf "net.ipv4.ip_forward=1\n" "/etc/sysctl.conf"
sudo sysctl -p /etc/sysctl.conf
INTERFACE="$(ip route show | grep default | awk '{print $5}')"
sudo iptables -t nat -A POSTROUTING -o $INTERFACE -j MASQUERADE
sudo DEBIAN_FRONTEND=noninteractive apt-get -y install iptables-persistent
sudo dpkg-reconfigure -p critical iptables-persistent
'''

    node_conf1 = {
        "Name":"n2",
        "VMs":[
            {"Name": "DBServern2",
             "OS": "ubuntu/xenial64",
             "Nets": [{"NetType": "internal", "IP": "172.16.2.1"}],
             "Roles":["PlaybookRoleName"]
            },
            {"Name": "routern2",
             "OS": "ubuntu/xenial64",
             "Nets": [{"NetType": "bridge", "IP":"172.16.20.20"},
                      {"NetType": "internal", "IP": "172.16.2.100"}
                     ],
             "Roles": ["PlaybookRoleName"]}]}

    assert build_node(exp_name, node_conf1, '/proj/teaching/IS613') == r'''# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure(2) do |config|
  config.vm.box_check_update = false
  config.vm.synced_folder "/share/ven/esys", "/share/ven/esys", create: true
  config.vm.synced_folder "/proj/teaching/IS613/esys", "/proj/teaching/IS613/esys", create: true,
    mount_options: ['rw', 'exec']
  config.vm.define "DBServern2" do |node|
    node.vm.box = "ubuntu/xenial64"
    node.vm.network "private_network", ip: "172.16.2.1"
    node.vm.provision "shell", path: "DBServern2.conf.sh"
  end
  config.vm.define "routern2" do |node|
    node.vm.box = "ubuntu/xenial64"
    node.vm.network "public_network", ip: "172.16.20.20", bridge:"ethtest1"
    node.vm.network "private_network", ip: "172.16.2.100"
    node.vm.provision "shell", path: "routern2.conf.sh"
  end
end
'''
    exp_conf = {
        "ExperimentDomainName":"OTTEST.OTTestbed.ncl.sg",
        "NSfile":"Path2NSfile",
        "Nodes":[
            {
                "Name":"n1",
                "VMs":[
                    {
                        "Name" : "win7n1",
                        "OS": "win7boxname",
                        "Password": "Passw0rd!ncl",
                        "Gateway": "172.16.1.100",
                        "Nets":[{"NetType": "internal", "IP": "172.16.1.1"}]
                    }
                ]
            },
            {
                "Name":"n2",
                'Type':'Gateway',
                "VMs":[
                    {
                        "Name" : "DBServern2",
                        "OS": "ubuntu/xenial64",
                        "Nets":[{"NetType": "internal", "IP": "172.16.2.1"}],
                    },
                    {
                        "Name" : "routern2",
                        "OS": "ubuntu/xenial64",
                        "Nets":[{"NetType": "bridge", "IP":"172.16.20.20"},
                                {"NetType": "internal", "IP": "172.16.2.100"}]
                    }
                ]
            }]
        }
    assert build_host_file(exp_conf) == '''win7n1,172.16.1.1
DBServern2,172.16.2.1
routern2,172.16.20.20
routern2,172.16.2.100
'''
    assert build_exp_ansible_inventory(exp_conf) == '''[nodes]
n1.OTTEST.OTTestbed.ncl.sg
n2.OTTEST.OTTestbed.ncl.sg

[VMn1]
win7n1

[VMn1:vars]
ansible_ssh_common_args= '-F /proj/OTTestbed/OTTEST/n1/ssh.config -o ProxyCommand="ssh -W %h:%p -q n1.OTTEST.OTTestbed.ncl.sg"'

[VMn2]
DBServern2
routern2

[VMn2:vars]
ansible_ssh_common_args= '-F /proj/OTTestbed/OTTEST/n2/ssh.config -o ProxyCommand="ssh -W %h:%p -q n2.OTTEST.OTTestbed.ncl.sg"'

'''
    assert build_ansible_palybook_up_vm(exp_conf) == '''- name: Install vagrant and virtualbox
  hosts: n1.OTTEST.OTTestbed.ncl.sg, n2.OTTEST.OTTestbed.ncl.sg
  tasks:
    - name: install virtualbox
      apt: name=virtualbox
      become: true
    - name: install vagrant via builder deb package
      apt: deb="/share/ven/vagrant.deb"
      become: true
    - name: check if vagrant is installed
      shell: dpkg-query -s vagrant | grep 'install ok installed'
      register: deb_check
      failed_when: deb_check.rc != 0
- name: Run vagrant up on n1
  hosts: n1.OTTEST.OTTestbed.ncl.sg
  tasks:
    - name: Make local disk /dev/sda3 and work as virtualbox home dir.
      script: /share/ven/bin/mkfs.sda3.sh
      become: true
    - name: Set environment variable VAGRANT_CWD / VAGRANT_HOME to let user run vagrant anywhere / share same boxes.
      script: /share/ven/bin/node_conf.py env "/proj/OTTestbed/OTTEST/n1/"
      become: true
    - name: start up vagrant on n1
      command: vagrant up  chdir=/proj/OTTestbed/OTTEST/n1/
    - name: Cat ssh config out
      shell: vagrant ssh-config > ssh.config
      args:
        chdir: /proj/OTTestbed/OTTEST/n1/
    - name: Setup ssh config on node
      shell: cat ssh.config | tee --append /etc/ssh/ssh_config
      become: true
      args:
        chdir: /proj/OTTestbed/OTTEST/n1/
- name: Run vagrant up on n2
  hosts: n2.OTTEST.OTTestbed.ncl.sg
  tasks:
    - name: Make local disk /dev/sda3 and work as virtualbox home dir.
      script: /share/ven/bin/mkfs.sda3.sh
      become: true
    - name: Set environment variable VAGRANT_CWD / VAGRANT_HOME to let user run vagrant anywhere / share same boxes.
      script: /share/ven/bin/node_conf.py env "/proj/OTTestbed/OTTEST/n2/"
      become: true
    - name: start up vagrant on n2
      command: vagrant up  chdir=/proj/OTTestbed/OTTEST/n2/
    - name: Cat ssh config out
      shell: vagrant ssh-config > ssh.config
      args:
        chdir: /proj/OTTestbed/OTTEST/n2/
    - name: Setup ssh config on node
      shell: cat ssh.config | tee --append /etc/ssh/ssh_config
      become: true
      args:
        chdir: /proj/OTTestbed/OTTEST/n2/
- name: Configure vagrant accessability and dir
  hosts: n1.OTTEST.OTTestbed.ncl.sg, n2.OTTEST.OTTestbed.ncl.sg
  become: true
  tasks:
    - name: Remove vagrant creator_uid in case vagrant creator-checking.
      shell: rm -f $(find /proj/OTTestbed/OTTEST/ | grep creator_uid)
    - name: Let group have rw to dir, so group can run vagrant under the dir.
      shell: chmod g+rw -R /proj/OTTestbed/OTTEST
'''
    assert build_ansible_roles("node", ["Playbook1", 'Playbook2']) == \
    '''- name: Install roles on node
  hosts: node
  become: true
  roles:
    - {role: Playbook1 }
    - {role: Playbook2 }
'''

    assert build_exp_nsfile(exp_conf) == '''set ns [new Simulator]
source tb_compat.tcl

# Set node.
set n1 [$ns node]
tb-set-node-os $n1 Ubuntu16.04.3-amd64
set n2 [$ns node]
tb-set-node-os $n2 Ubuntu16.04.3-amd64
'''
    exp_conf['LANs'] = [
        {"Subnet": "172.16.1.", "LAN":[("n1", "1"), ("n2", "2")]},
        {"Subnet" : "172.16.2.", "LAN" : [("n1", "11"), ("n2", "12")]}
    ]
    assert build_host_file(exp_conf) == '''win7n1,172.16.1.1
DBServern2,172.16.2.1
routern2,172.16.20.20
routern2,172.16.2.100
n1,172.16.1.1
n2,172.16.1.2
n1,172.16.2.11
n2,172.16.2.12
'''

    assert build_exp_nsfile(exp_conf) == '''set ns [new Simulator]
source tb_compat.tcl

# Set node.
set n1 [$ns node]
tb-set-node-os $n1 Ubuntu16.04.3-amd64
set n2 [$ns node]
tb-set-node-os $n2 Ubuntu16.04.3-amd64

# Set LAN.
set lan0 [$ns make-lan "$n1 $n2" 10Gb 0ms]
set lan1 [$ns make-lan "$n1 $n2" 10Gb 0ms]

# Set node ip.
tb-set-ip-lan $n1 $lan0 172.16.1.1
tb-set-ip-lan $n2 $lan0 172.16.1.2
tb-set-ip-lan $n1 $lan1 172.16.2.11
tb-set-ip-lan $n2 $lan1 172.16.2.12

# Set route and adjust configure.
$ns rtproto Static
tb-set-node-startcmd $n1 "/share/ven/bin/install2local.sh 172.16.2.12 > /tmp/install2local.log 2>&1"
tb-set-node-startcmd $n2 "/share/ven/bin/install2local.sh 172.16.2.12 > /tmp/install2local.log 2>&1"

# Go!
$ns run
'''
    exp_conf = {
        "ExperimentDomainName":"OTTEST.OTTestbed.ncl.sg",
        "Reserve":"pc11h",
        "Nodes":[{"Name":"n1"},
                 {"Name":"n2", 'Type':'Gateway'}]}
    assert build_exp_nsfile(exp_conf) == '''set ns [new Simulator]
source tb_compat.tcl

# Set node.
set n1 [$ns node]
tb-set-node-os $n1 Ubuntu16.04.3-amd64
tb-fix-node $n1 pc11h
set n2 [$ns node]
tb-set-node-os $n2 Ubuntu16.04.3-amd64
'''
    exp_conf = {
        "ExperimentDomainName":"OTTEST.OTTestbed.ncl.sg",
        "Reserve":"pc11h  , pc16h, pc17g,",
        "Nodes":[{"Name":"n1"},
                 {"Name":"n2", 'Type':'Gateway'}]}
    assert build_exp_nsfile(exp_conf) == '''set ns [new Simulator]
source tb_compat.tcl

# Set node.
set n1 [$ns node]
tb-set-node-os $n1 Ubuntu16.04.3-amd64
tb-fix-node $n1 pc11h
set n2 [$ns node]
tb-set-node-os $n2 Ubuntu16.04.3-amd64
tb-fix-node $n2 pc16h
'''
    # build_install_node
    assert build_install_node({}, 'exp', 'team') == ('', '')
    assert build_install_node({'Name':'n1', 'install':['install.web']}, 'exp', 'team')\
        == ('','''ansible-playbook -i inventory /share/ven/soft/install.web.yml --extra-vars "vhosts=n1.exp.team.ncl.sg"
''')
    assert build_install_node({'Name':'n1', 'install':['install.web'], 'run':['ls']}, 'exp', 'team')\
        == ('ls\n', '''ansible-playbook -i inventory /share/ven/soft/install.web.yml --extra-vars "vhosts=n1.exp.team.ncl.sg"
''')
    assert build_install_node({'Name':'n1', 'install':['install.web'], 'run':['ls', 'ip route show']}, 'exp', 'team')\
        == ('''ls\nip route show\n''', '''ansible-playbook -i inventory /share/ven/soft/install.web.yml --extra-vars "vhosts=n1.exp.team.ncl.sg"
''')
    assert build_install_node({'Name':'n1', 'install':['install.web', 'install.db']}, 'exp', 'team')\
        == ('', '''ansible-playbook -i inventory /share/ven/soft/install.web.yml --extra-vars "vhosts=n1.exp.team.ncl.sg"
ansible-playbook -i inventory /share/ven/soft/install.db.yml --extra-vars "vhosts=n1.exp.team.ncl.sg"
''')
    assert build_install_node({'Name':'n1', 'install':['install.splunk']}, 'exp', 'team')\
        ==('''/share/ven/soft/install.splunk.sh
''', '')
    assert build_install_node({'Name':'n1', 'VMs':[{'Name':'v1n1', 'install':[
        'install.web', 'install.db']}]}, 'exp', 'team')\
        == ('', '''ansible-playbook -i inventory /share/ven/soft/install.web.yml --extra-vars "vhosts=v1n1"
ansible-playbook -i inventory /share/ven/soft/install.db.yml --extra-vars "vhosts=v1n1"
''')
    assert build_install_node({'Name':'n1', 'VMs':[{'Name':'v1n1', 'install':[
        'install.splunk', 'install.snort 172.16.1.3']}]}, 'exp', 'team')\
        == ('''/share/ven/soft/install.splunk.sh v1n1 n1 exp team
/share/ven/soft/install.snort.sh v1n1 n1 exp team 172.16.1.3
''', '')
    # produce_cmd4gateway
    assert produce_cmd4gateway({'Nodes':[{'Name':'n5', "Type": "Gateway"},{'Name':'n1'}], 
        'LANs':[{'Subnet':'172.16.1.', 'LAN':[['n1','2'],['n5','100']]}]}) == \
        ('172.16.1.100', 'n5', 'sudo /share/ven/bin/chNetwork.py 172.16.1.100\n')
    assert produce_cmd4gateway({'Nodes':[{'Name':'n5', "Type": "Gateway"},{'Name':'n1', 'VMs':[
        {'Name':'rn1','Forward':1,'Nets':[{"IP": "172.16.4.100","NetType": "internal"},{"IP": "172.16.1.44",
        "NetType": "bridge"}]}]}],
        'LANs':[{'Subnet':'172.16.1.', 'LAN':[['n1','2'],['n5','100']]}]}) == \
        ('172.16.1.100', 'n5', 'sudo /share/ven/bin/chNetwork.py 172.16.1.100\nsudo ip route add 172.16.4.0/24 via 172.16.1.44\n')

    helpfunc.get_interface_by_ip = func1
    helpfunc.get_host_routertable = func2

def produce_nsfile(exp_conf):
    '''The func produce nsfile.'''
    log("produce_nsfile")
    exp_home_dir = get_exp_home_dir(exp_conf)
    # Create vagrantfile for every node.
    print "Produce NSfile in the dir [%s]" % exp_home_dir
    nsfilename = os.path.join(exp_home_dir, 'NSfile.txt')
    with open(nsfilename, 'w') as afile:
        afile.write(build_exp_nsfile(exp_conf))

def produce_vf(exp_conf):
    log("produce_vf")
    '''The func produce vf based on exp_conf.'''
    exp_home_dir = get_exp_home_dir(exp_conf)

    # Create vagrantfile for every node.
    print "Produce vagrantfile for every node in the dir [%s]" % exp_home_dir
    build_exp_vf(exp_conf, exp_home_dir)
    #build_exp("VNconf.json", "./vagrant" )
    #build_exp("VNconf.json", "/proj/NYPSOC" )
def produce_ansible(exp_conf):
    '''The func produce vf based on exp_conf.'''
    exp_home_dir = get_exp_home_dir(exp_conf)

    print "Produce the ansible inventory and playbook files in the dir [%s]"\
        % exp_home_dir
    build_exp_ansible(exp_conf, exp_home_dir)

def produce_hostfile(exp_conf):
    '''The func produce nsfile.'''
    exp_home_dir = get_exp_home_dir(exp_conf)
    # Create vagrantfile for every node.
    print "Produce NSfile in the dir [%s]" % exp_home_dir
    filename = os.path.join(exp_home_dir, 'hosts.txt')
    with open(filename, 'w') as afile:
        afile.write(build_host_file(exp_conf))

def produce_script(exp_conf):
    '''The func produce script for up VMs and configure, installing application.'''
    if os.name == 'nt':
        home_dir = './vagrant'
    else:
        home_dir = '/proj'
    names = exp_conf['ExperimentDomainName'].split('.')
    exp_name = names[0]
    team_name = names[1]
    exp_home_dir = get_exp_home_dir(exp_conf)

    print "Produce script for every node in the dir [%s]" % exp_home_dir
    (gateway_ip, gateway_name, gateway_cmd) = produce_cmd4gateway(exp_conf)
    if gateway_ip == '':
        print 'Warn: cannot find gateway IP.'
    builder_cmd = ''
    install_all_cmd = ''
    for node_conf in exp_conf['Nodes']:
        node_name = node_conf["Name"]
        script = ''
        node_full_name = node_name+'.'+exp_name+'.'+team_name+'.ncl.sg'
        if node_name == gateway_name:
            script += gateway_cmd
            script += '\n'
        if (node_conf.has_key('VMs')) and (node_conf['VMs'] != {}):
            script += '/share/ven/bin/node_run.sh %s %s %s %s' % \
                (node_name, exp_name, team_name, gateway_ip)
            script += '\n'
        (node_cmd, tbcmd) = build_install_node(node_conf, exp_name, team_name)
        script += node_cmd
        builder_cmd += tbcmd
        if script != '':
            fdir = os.path.join(exp_home_dir, node_name)
            if not os.path.exists(fdir):
                log("produce_script makedirs")
                os.makedirs(fdir)
            fname = os.path.join(fdir, node_name+'.sh') 
            with open(fname, 'w') as afile:
                head = '#!/bin/bash -x\n# Donot change. Auto-generated file.\n'
                head += 'cd /proj/%s/%s/\n' % (team_name, exp_name)
                afile.write(head)
                afile.write(script)
            st = os.stat(fname)
            os.chmod(fname, st.st_mode | stat.S_IEXEC)
            install_all_cmd += "ssh %s '%s'" % (node_full_name, fname)
            install_all_cmd += '\n'
    if builder_cmd != '':
        fname = os.path.join(exp_home_dir, 'install.soft.sh') 
        with open(fname, 'w') as afile:
            head = '#!/bin/bash -x\n# Donot change. Auto-generated file.\n'
            head += 'cd /proj/%s/%s/\n' % (team_name, exp_name)
            afile.write(head)
            afile.write(builder_cmd)
        st = os.stat(fname)
        os.chmod(fname, st.st_mode | stat.S_IEXEC)
        install_all_cmd += "%s" % fname
        install_all_cmd += '\n'
    if install_all_cmd != '':
        fname = os.path.join(exp_home_dir, 'install.all.sh') 
        with open(fname, 'w') as afile:
            head = '#!/bin/bash -x\n# Donot change. Auto-generated file.\n'
            afile.write(head)
            afile.write(install_all_cmd)        
        st = os.stat(fname)
        os.chmod(fname, st.st_mode | stat.S_IEXEC)
        print fname

def produce_runcmd(exp_conf):
    '''The func produce runcmd for up VMs and configure .'''
    produce_script(exp_conf)
    log("produce_runcmd")
    return
    if os.name == 'nt':
        home_dir = './vagrant'
    else:
        home_dir = '/proj'
    names = exp_conf['ExperimentDomainName'].split('.')
    exp_name = names[0]
    team_name = names[1]

    log("produce_runcmd")
    #Move vagrant box to project dir on users.ncl.sg
    box_path = os.path.join(home_dir, team_name, 'vnetwork', 'vagrant')
    if not os.path.exists(box_path):
        print 'Box path [%s] does not exist. Please run the following'\
            'command on users.ncl.sg to move boxes to the project directory.'\
            '\n/share/ven/bin/mv.box.py %s'%\
            (box_path, os.path.join(home_dir, team_name))
    print 'Run the following command to setup VMs...'
    (gateway_ip, gateway_node, out_str) = produce_cmd4gateway(exp_conf)
    node_full_name = gateway_node+'.'+exp_name+'.'+team_name+'.ncl.sg'
    cmd = 'echo -e "%s" | ssh %s' % (out_str, node_full_name)
    print cmd
    # Produce cmd for nodes with MVs
    for node_conf in exp_conf['Nodes']:
        if (node_conf.has_key('VMs')) and (node_conf['VMs'] != {}):
            node_name = node_conf["Name"]
            node_full_name = node_name+'.'+exp_name+'.'+team_name+'.ncl.sg'
            print "ssh %s '/share/ven/bin/node_run.sh %s %s %s %s'" % \
                (node_full_name, node_name, exp_name, team_name, gateway_ip)
def run_ansible(exp_conf):
    '''unused func.'''
    if os.name == 'nt':
        home_dir = './vagrant'
    else:
        home_dir = '/proj'
    names = exp_conf['ExperimentDomainName'].split('.')
    exp_name = names[0]
    team_name = names[1]
    exp_home_dir = os.path.join(home_dir, team_name, exp_name)
    inventory_file_name = os.path.join(exp_home_dir, "inventory")
    playbook_file_name = os.path.join(exp_home_dir, FILENAME_UP_VM)
    # Check if the box path is ready?
    box_path = os.path.join(home_dir, team_name, 'vnetwork', 'vagrant')
    if not os.path.exists(box_path):
        print 'Error: Box path [%s] does not exist. Please run the '\
            'following command on user.ncl.sg .\n/share/ven/bin/mv.box.py'\
            ' %s'%(box_path, os.path.join(home_dir, team_name))
        exit()
    print "ansible-playbook -i %s -vvv %s" % \
        (inventory_file_name, playbook_file_name)
    out_str = subprocess.check_output("ansible-playbook -i %s -vvv %s" % \
        (inventory_file_name, playbook_file_name), shell=True)
    print out_str
    playbook_file_name = os.path.join(exp_home_dir, FILENAME_BUILD_APP)
    print "ansible-playbook -i %s -vvv %s" % \
        (inventory_file_name, playbook_file_name)
    with open(FILENAME_ANSIBLE_LOG, 'a') as logfile:
        proc = subprocess.Popen(
            ("ansible-playbook -i %s -vvv %s" % \
            (inventory_file_name, playbook_file_name)).split(),
            shell=True,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        for line in iter(proc.stdout.readline, ''):
            sys.stdout.write(line)
            logfile.write(line)
        proc.wait()

def main():
    '''Main func.'''
    if (len(sys.argv) == 2) and (sys.argv[1] == "test"):
        test()
        print "Pass all test"
        exit()
    if os.name == 'nt':
        home_dir = './vagrant'
    else:
        home_dir = '/proj'
    if (len(sys.argv) == 3) and (sys.argv[1] == "ns"):
        exp_conf = get_exp_conf(sys.argv[2])
        produce_nsfile(exp_conf)
    elif (len(sys.argv) == 3) and (sys.argv[1] == "vf"):
        exp_conf = get_exp_conf(sys.argv[2])
        produce_vf(exp_conf)
    elif (len(sys.argv) == 3) and (sys.argv[1] == "ansible"):
        exp_conf = get_exp_conf(sys.argv[2])
        produce_ansible(exp_conf)
        #build_exp("VNconf.json", "./vagrant" )
    elif (len(sys.argv) == 3) and (sys.argv[1] == "runcmd"):
        #Show the cmd to run on node#
        exp_conf = get_exp_conf(sys.argv[2])
        #produce_runcmd(exp_conf)
        produce_script(exp_conf)

    elif (len(sys.argv) == 3) and (sys.argv[1] == "check"):
        exp_conf = get_exp_conf(sys.argv[2])
        print "OK"
    elif (len(sys.argv) == 3) and (sys.argv[1] == "run"):
        exp_conf = get_exp_conf(sys.argv[2])
        run_ansible(exp_conf)
    elif (len(sys.argv) == 4) and (sys.argv[1] == "vhalt"):
        exp_conf = get_exp_conf(sys.argv[2])
        names = exp_conf['ExperimentDomainName'].split('.')
        exp_name = names[0]
        team_name = names[1]
        exp_home_dir = os.path.join(home_dir, team_name, exp_name)
        inventory_file_name = os.path.join(exp_home_dir, "inventory")
        print 'ansible -i {0} {1}.{2} -a "vagrant halt  '\
            'chdir=/proj/NYPSOC/EnterpriseNetwork/n"'.format(
                inventory_file_name, sys.argv[2],
                exp_conf['ExperimentDomainName'])
        with open(FILENAME_ANSIBLE_LOG, 'a') as logfile:
            proc = subprocess.Popen(
                ('ansible -i {0} {1}.{2} -a "vagrant halt  '\
                'chdir=/proj/NYPSOC/EnterpriseNetwork/n"'.format(
                    inventory_file_name, sys.argv[3],
                    exp_conf['ExperimentDomainName'])).split(), shell=True,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            for line in iter(proc.stdout.readline, ''):
                sys.stdout.write(line)
                logfile.write(line)
            proc.wait()
    else:
        print '''{0} vf|ansible|run virtualNetwork.json
        vf :        Produce the vagrantfiles.
        ansible :   Produce inventory and playbook files.
        run :       Run ansible playbook files.
        ns :        create NSfile for
        runcmd :    Produce run command for preparing VMs after running vf .

    {0} vhalt virtualNetwork.json node_name
        vhalt vms on node_name

    {0} test
    '''.format(sys.argv[0])


if __name__ == "__main__":
    main()
