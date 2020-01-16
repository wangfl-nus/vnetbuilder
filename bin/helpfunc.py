#!/bin/python
# VM define requirement
DEFAULT_USERNAME = "user"
DEFAULT_PASSWORD = "Passw0rd!ncl"
DEFAULT_NETMASK = "255.255.255.0"
DEFAULT_INTERNAL_NET_NAME = "intranal"



def sep_ip_set(astr):
    """ The func analysis NS file to get the IP set line and 
    return the splited line list.
    """
    lines = astr.split('\n')
    node_ip_list = []
    for line in lines:
        words = line.split()
        if len(words) == 0:
            continue
        if words[0] == "tb-set-ip":
            node_ip_list.append(words)
        elif words[0] == "tb-set-ip-lan":
            node_ip_list.append(words)
            
    print str(node_ip_list)
    return node_ip_list
def get_node_ip(node_name, lan_name, node_ip_list):
    """ The func get the node_name with lan_name in node_ip_list."""
    for node_ip_line in node_ip_list:
        if (node_name == node_ip_line[1]) or (("$"+node_name) == node_ip_line[1]):
            if lan_name == "":
                if node_ip_line[0] == "tb-set-ip":
                    return node_ip_line[2]
            else:
                if node_ip_line[0] != "tb-set-ip-lan":
                    continue
                if(lan_name == node_ip_line[2]) or (("$"+lan_name) == node_ip_line[2]):
                    return node_ip_line[3]
    return ''
    
import os
def get_host_routertable(node_name):
    import subprocess
    if os.name == 'nt':
        # For test.
        ROUTE_CMD = "route print %s"
    else:
        ROUTE_CMD = "ssh -o 'StrictHostKeyChecking no' %s 'ip route show'"
    return subprocess.check_output(ROUTE_CMD%node_name, shell=True)
    
def get_interface_by_ip(vmip, host_route_table):
    ''' The func get host's net interface by vm's ip from host's route table.
    Such as: vm ip 172.16.20.10, Host's route tabls:
    lqun4583@n1:~$ ip route show
default via 172.16.20.100 dev eth5 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.145 
10.64.0.0/16 via 10.16.0.1 dev eth0 
172.16.20.0/24 dev eth5  proto kernel  scope link  src 172.16.20.1
    return eth5
    '''
    if os.name == 'nt':
        return 'ethtest'
    lines = host_route_table.split('\n')
    vmip_network = vmip[0:vmip.rfind('.')]+'.0/24'
    for line in lines:
        if line.find('/') > 0:
            #print "Network: " + line
            words = line.split()
            network = words[0]
            if network == vmip_network:
                return words[2]
            pass
    return ''
def get_gateway_ip_by_first_ip(myip):
    '''The func guess the gateway ip by it's first ip.
    The rule is the same subnet and gateway ip is 100.
    Such as myip:172.16.2.1 return 172.16.2.100
    '''
    gateway_ip = myip[0:myip.rfind('.')]+'.100'
    return gateway_ip
    
def test_sep_ip_set():
    assert sep_ip_set("") == []
    assert sep_ip_set("tb-set-ip $n1 172.16.20.1") == [['tb-set-ip', '$n1', '172.16.20.1']]
    input1 = '''
tb-set-ip $n1 172.16.20.1
tb-set-ip-lan $n2 $workLan 172.16.20.2
tb-set-ip-lan $n2 $MngtLan 172.16.30.2
tb-set-ip-lan $n3 $workLan 172.16.20.3
tb-set-ip-lan $n3 $MngtLan 172.16.30.3'''
    node_ip_list = sep_ip_set(input1)
    assert node_ip_list == [['tb-set-ip', '$n1', '172.16.20.1'], ['tb-set-ip-lan', '$n2', '$workLan', '172.16.20.2'], ['tb-set-ip-lan', '$n2', '$MngtLan', '172.16.30.2'], ['tb-set-ip-lan', '$n3', '$workLan', '172.16.20.3'], ['tb-set-ip-lan', '$n3', '$MngtLan', '172.16.30.3']]
    #get_node_ip
    assert get_node_ip("n1", "", node_ip_list) == "172.16.20.1"
    assert get_node_ip("$n1", "", node_ip_list) == "172.16.20.1"
    assert get_node_ip("n1", "lan", node_ip_list) == ""
    assert get_node_ip("n2", "", node_ip_list) == ""
    assert get_node_ip("n2", "workLan", node_ip_list) == "172.16.20.2"
    assert get_node_ip("$n2", "workLan", node_ip_list) == "172.16.20.2"
    assert get_node_ip("n2", "MngtLan", node_ip_list) == "172.16.30.2"
    
    #get_interface_by_ip
    routetable1="""
    default via 172.16.20.100 dev eth5 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.145 
10.64.0.0/16 via 10.16.0.1 dev eth0 
172.16.20.0/24 dev eth5  proto kernel  scope link  src 172.16.20.1
"""
    if os.name == 'nt':
        assert get_interface_by_ip("172.16.20.10", routetable1) == "ethtest"
    else:
        assert get_interface_by_ip("172.16.20.10", routetable1) == "eth5"
    
    # get_gateway_ip_by_first_ip
    assert get_gateway_ip_by_first_ip("172.16.20.10") == "172.16.20.100"
    assert get_gateway_ip_by_first_ip("172.16.2.1") == "172.16.2.100"
    

if __name__ == "__main__":
    import sys     
    if (len(sys.argv) == 2) and (sys.argv[1] == "test"):
        test_sep_ip_set()   
        print("Pass all test")
        exit()
    else:
        import json
        path2joson_file = "net.json"
        with open(path2joson_file, "r") as f:
            vm_requirement_str = f.read()

        require = json.loads(vm_requirement_str)
        print json.dumps(require, indent=4, separators=(',', ': '))
        #print str(require)

        #print require['Nodes'][0]['VMs'][0]['Nets'][0]["IP"]
