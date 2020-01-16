#!/usr/bin/python
import subprocess
import sys
import os
import time
import logging
LOG_ENTITY = 'chNetwork'

'''
Change route setup on NCL testbed.
liqun@ncl.sg 2017-8-18
'''
# Define interactive mode.
interactive = False
# If the network is simple 2layer network, network gateway with multi-zone
# router, set it true.
NET2LAYER = True


def usage():
    print("""# For every node, gateway is the node to access internet for all nodes. 
# Any IP of the gateway is OK.
$ %s gateway_ip 
#For desktop or server with one work network interface and one management interface.
$ %s
# For firewall,
$ %s firewall
# For router which connect with lan and firewall. such as: %s N.N.N.N eth2
$ %s router firewall_IP interface2Firewall
    """)
'''
lqun4583@n2:~$ ip route show
default via 10.16.0.1 dev eth0
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.41
172.16.1.0/24 dev eth4  proto kernel  scope link  src 172.16.1.2
172.16.2.2 via 172.16.1.3 dev eth4
172.16.2.3 via 172.16.1.3 dev eth4
172.16.3.2 via 172.16.1.3 dev eth4
172.16.3.3 via 172.16.1.3 dev eth4
172.16.3.4 via 172.16.1.3 dev eth4
172.16.3.5 via 172.16.1.3 dev eth4
172.16.4.2 via 172.16.1.3 dev eth4
172.16.4.3 via 172.16.1.3 dev eth4
172.16.4.4 via 172.16.1.3 dev eth4
172.16.4.5 via 172.16.1.3 dev eth4
172.16.4.6 via 172.16.1.3 dev eth4
172.16.5.2 via 172.16.1.3 dev eth4
172.16.5.3 via 172.16.1.3 dev eth4

After run, change to
default via 172.16.1.3 dev eth4
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.41
10.64.0.0/16 via 10.16.0.1 dev eth0
172.16.1.0/24 dev eth4  proto kernel  scope link  src 172.16.1.2

For Main firewall, it's route table is different.
lqun4583@n6:~$ ip route show
default via 10.16.0.1 dev eth0
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.105
172.16.1.2 via 172.16.3.3 dev eth5
172.16.1.3 via 172.16.3.3 dev eth5
172.16.2.2 via 172.16.3.4 dev eth5
172.16.2.3 via 172.16.3.4 dev eth5
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.5
172.16.4.0/24 dev eth4  proto kernel  scope link  src 172.16.4.2
172.16.5.2 via 172.16.3.2 dev eth5
172.16.5.3 via 172.16.3.2 dev eth5
To:
default via 10.16.0.1 dev eth0
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.105
172.16.2.0/24 via 172.16.3.4 dev eth5
172.16.1.0/24 via 172.16.3.3 dev eth5
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.5
172.16.4.0/24 dev eth4  proto kernel  scope link  src 172.16.4.2
172.16.5.0/24 via 172.16.3.2 dev eth5

'''

change_gw_fmt = "sudo ip route change default via %s dev %s"
del_route_fmt = "sudo ip route del %s"
add_route_fmt = "sudo ip route add %s via %s"
users_network = '10.64.0.0/16'
gw_to_users = '10.16.0.1'


def run_cmd(cmd, run):

    if not run :
        print "-$ " + cmd
    else:
        logging.getLogger(LOG_ENTITY).info("Run cmd[%s]" % cmd)
        return subprocess.check_output(cmd, shell=True)

def get_route():
    i = 0
    while i < 100:
        output = run_cmd("ip route show", True)
        if output != '':
            return output
        logging.getLogger(LOG_ENTITY).info("Get route[], network is not ready, wait 10s")
        time.sleep(10)
        i += 1

def add_users_route(run):
    run_cmd(add_route_fmt%(users_network, gw_to_users), run);
def analysis_gw_netgw(output, net_gateway_ip=''):
    '''The func analysis route show and return this node's default gateway ip,
    gateway's interface.
    Caller can provide network's gateway_ip then route item to gateway_ip is 
    default gateway of the node.
    '''
    alist = output.split('\n')
    ip_network = net_gateway_ip[0:net_gateway_ip.rfind('.')]+'.0/24'
    # First round, get default gateway and all networks including guessed new default gateway and guessed new network.
    for astring in alist:
        if astring.find('default') >= 0 :
            pass #print "Default: " + astring
        elif astring.find('/') > 0:
            #print "Network: " + astring
            ip_route_list = astring.split()
            network = ip_route_list[0]
            if network == ip_network:
                # net_gateway_ip in my local network which covered by network item.
                # 172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.2 
                return (net_gateway_ip, ip_route_list[2])
            pass
        elif (astring.find('$') > 0) or (astring.find('#') > 0) :
            #print "CmdLine: " + astring
            pass
        elif len(astring) == 0:
            #print "NilLine:" + astring
            pass
        else:
            #print "IpRoute: " + astring
            ip_route_list = astring.split()
            single_ip = ip_route_list[0]
            if single_ip == net_gateway_ip:
                default_gw = ip_route_list[2]
                default_interface = ip_route_list[4]
                return (default_gw, default_interface)

    print("Error: cannot get[%s]in IP route list"%(net_gateway_ip))
    return ('', '')
    exit()

def analysis_gw(output, default_gw='', default_interface='', gateway_ip=''):
    '''The func analysis route show and return this node's default gateway ip,
    gateway's interface, ip route item kept, net route item added.
    Caller can provide default_gw/interface.
    Caller can provide network's gateway_ip then route item to gateway_ip is 
    default gateway of the node.
    '''
    alist = output.split('\n')
    have_users_route = False
    run_cmd_num = 0
    new_gw = ""
    gw_interface = ""
    num_gw = 0
    gw_list = {}
    candidate_df_gw = ''
    single_ip_route = []
    new_net_route = []
    # First round, get default gateway and all networks including guessed new default gateway and guessed new network.
    for astring in alist:
        if astring.find('default') >= 0 :
            pass #print "Default: " + astring
        elif astring.find('/') > 0:
            #print "Network: " + astring
            pass
        elif (astring.find('$') > 0) or (astring.find('#') > 0) :
            #print "CmdLine: " + astring
            pass
        elif len(astring) == 0:
            #print "NilLine:" + astring
            pass
        else:
            #print "IpRoute: " + astring
            ip_route_list = astring.split(" ")
            new_gw = ip_route_list[2]
            single_ip = ip_route_list[0]
            if single_ip == gateway_ip:
                default_gw = new_gw
                default_interface = ip_route_list[4]
            ip_network = single_ip[0:single_ip.rfind('.')]+'.0/24'
            if new_gw not in gw_list:
                gw_interface = ip_route_list[4]
                gw_list[new_gw] = (gw_interface, 1, single_ip, ip_network)
                num_gw += 1
            else:
                (gw_interface, num, aip, aip_network) = gw_list[new_gw]
                if ip_network != aip_network:
                    #print("single_ip[%s], not in [%s], new_gw[%s]"%(single_ip, str(aip_network), new_gw))
                    found = False
                    for (tmp_net, tmp_gw, tmp_interface) in new_net_route:
                        if ip_network == tmp_net:
                            found = True
                            break
                    if not found:
                        new_net_route.append(tuple([ip_network, new_gw, gw_interface]))
                    if candidate_df_gw != '' and candidate_df_gw != new_gw:
                        print("Error:New ip route 's gateway[%s] maybe the default gateway, != %s"%
                            (new_gw, candidate_df_gw))
                    candidate_df_gw = new_gw
                gw_list[new_gw] = (gw_interface, num+1, aip, aip_network)

    if num_gw == 1:
        # leaf node, all other nodes go through same gateway and interface.
        print "This is a leaf node , all other nodes go through gateway (%s) by interface (%s)" % (new_gw, gw_interface)
    max_num = 0
    #print("gw_list:" + str(gw_list))
    for gw,(interface, num, aip, ip_network) in gw_list.items():
        if num > max_num:
            new_gw = gw
            gw_interface = interface
            max_num = num
        if num == 1:
            single_ip_route.append(tuple([aip,gw]))
        else:
            new_net_route.append(tuple([ip_network, gw, interface]))
    if default_gw != '':
        new_gw = default_gw
        gw_interface = default_interface
    ip_route = []
    for (aip, gw) in single_ip_route:
        if gw != new_gw:
            ip_route.append(tuple([aip, gw]))
    net_route = []
    for (ip_network, gw, interface) in new_net_route:
        if gw != new_gw:
            net_route.append(tuple([ip_network, gw, interface]))
    print("analysis_gw:%s - %s [%s][%s]"%(new_gw, gw_interface, str(ip_route), str(net_route)))
    return (new_gw, gw_interface, ip_route, net_route)
def test_analysis_gw():
    ''' The func test analysis_gw().'''
    output1 = '''172.16.1.0/24 dev eth4  proto kernel  scope link  src 172.16.1.2
172.16.2.2 via 172.16.1.3 dev eth4
'''
    output2 = '''172.16.1.0/24 dev eth4  proto kernel  scope link  src 172.16.1.2
172.16.2.2 via 172.16.1.3 dev eth4
172.16.2.3 via 172.16.1.3 dev eth4
'''
    # n1 in ot
    output3 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.59 
172.16.1.0/24 dev eth5  proto kernel  scope link  src 172.16.1.2 
172.16.2.2 via 172.16.1.3 dev eth5 
172.16.2.3 via 172.16.1.3 dev eth5 
172.16.2.4 via 172.16.1.3 dev eth5 
172.16.3.2 via 172.16.1.3 dev eth5 
172.16.3.3 via 172.16.1.3 dev eth5 
172.16.3.4 via 172.16.1.3 dev eth5 
172.16.4.2 via 172.16.1.3 dev eth5 
172.16.4.3 via 172.16.1.3 dev eth5 
172.16.4.4 via 172.16.1.3 dev eth5 
172.16.4.5 via 172.16.1.3 dev eth5 
172.16.4.9 via 172.16.1.3 dev eth5 
172.16.5.0/24 dev eth4  proto kernel  scope link  src 172.16.5.4 
'''
    # n3 in otnet
    output4 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.78 
172.16.1.0/24 dev eth4  proto kernel  scope link  src 172.16.1.3 
172.16.2.0/24 dev eth5  proto kernel  scope link  src 172.16.2.2 
172.16.3.2 via 172.16.2.3 dev eth5 
172.16.3.3 via 172.16.2.4 dev eth5 
172.16.3.4 via 172.16.2.4 dev eth5 
172.16.4.2 via 172.16.2.4 dev eth5 
172.16.4.3 via 172.16.2.4 dev eth5 
172.16.4.4 via 172.16.2.4 dev eth5 
172.16.4.5 via 172.16.2.4 dev eth5 
172.16.4.9 via 172.16.2.4 dev eth5 
172.16.5.2 via 172.16.1.2 dev eth4 
172.16.5.3 via 172.16.1.2 dev eth4 
172.16.5.4 via 172.16.1.2 dev eth4 
172.16.5.10 via 172.16.1.2 dev eth4 
'''
    # n5 in otnet
    output5 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.79 
172.16.1.2 via 172.16.2.2 dev eth4 
172.16.1.3 via 172.16.2.2 dev eth4 
172.16.2.0/24 dev eth4  proto kernel  scope link  src 172.16.2.4 
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.3 
172.16.4.2 via 172.16.3.4 dev eth5 
172.16.4.3 via 172.16.3.4 dev eth5 
172.16.4.4 via 172.16.3.4 dev eth5 
172.16.4.5 via 172.16.3.4 dev eth5 
172.16.4.9 via 172.16.3.4 dev eth5 
172.16.5.2 via 172.16.2.2 dev eth4 
172.16.5.3 via 172.16.2.2 dev eth4 
172.16.5.4 via 172.16.2.2 dev eth4 
172.16.5.10 via 172.16.2.2 dev eth4 
'''
    # n1 in virtualnetwork
    output6 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.40 
172.16.1.2 via 172.16.3.3 dev eth5 
172.16.1.3 via 172.16.3.3 dev eth5 
172.16.2.2 via 172.16.3.4 dev eth5 
172.16.2.3 via 172.16.3.4 dev eth5 
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.2 
172.16.4.2 via 172.16.3.5 dev eth5 
172.16.4.3 via 172.16.3.5 dev eth5 
172.16.4.4 via 172.16.3.5 dev eth5 
172.16.4.5 via 172.16.3.5 dev eth5 
172.16.4.6 via 172.16.3.5 dev eth5 
172.16.5.0/24 dev eth4  proto kernel  scope link  src 172.16.5.3 

'''
    
    assert analysis_gw(output1) == ("172.16.1.3", "eth4", [], [])
    assert analysis_gw(output2) == ("172.16.1.3", "eth4", [], [])
    assert analysis_gw(output3) == ("172.16.1.3", "eth5", [], [])
    assert analysis_gw(output3, "","","172.16.3.4") == ("172.16.1.3", "eth5", [], [])
    assert analysis_gw(output4) == ("172.16.2.4", "eth5", [("172.16.3.2", "172.16.2.3")], [("172.16.5.0/24", "172.16.1.2", "eth4")])
    assert analysis_gw(output4, "","","172.16.3.4") == ("172.16.2.4", "eth5", [("172.16.3.2", "172.16.2.3")], [("172.16.5.0/24", "172.16.1.2", "eth4")])
    assert analysis_gw(output4, "","","172.16.4.2") == ("172.16.2.4", "eth5", [("172.16.3.2", "172.16.2.3")], [("172.16.5.0/24", "172.16.1.2", "eth4")])
    print(str(analysis_gw(output5, "","","172.16.4.2")))
    assert analysis_gw(output5, "","","172.16.4.2") == ("172.16.3.4", "eth5", [], [("172.16.5.0/24", "172.16.2.2", "eth4"), ("172.16.1.0/24", "172.16.2.2", "eth4")])
    
    assert analysis_gw_netgw(output3, "172.16.3.4") == ("172.16.1.3", "eth5")
    assert analysis_gw_netgw(output3, "172.16.4.2") == ("172.16.1.3", "eth5")
    assert analysis_gw_netgw(output6, "172.16.4.2") == ("172.16.3.5", "eth5")
    assert analysis_gw_netgw(output6, "172.16.3.5") == ("172.16.3.5", "eth5")
    
    
def sep_string(output, run, new_gw, new_gw_interface, single_ip_route=[], new_net_route=[]):
    '''The func change route on ouput of route table.'''
    alist = output.split('\n')
    have_users_route = False
    run_cmd_num = 0

# must add users route first, or sudo will fail after change the default route and sudo can not connect name server, it can not resolve the hostname.
    if output.find(users_network) < 0:
        add_users_route(run)
        run_cmd_num += 1
    for astring in alist:
        if astring.find('default') >= 0 :
            print "Default: " + astring
            if len(new_gw) > 0 :
                if astring.find(new_gw) < 0:
                    run_cmd(change_gw_fmt%(new_gw, new_gw_interface), run)
                    run_cmd_num += 1
            else :
                print "No new_gw. Do not chanage default gateway."

        elif astring.find('/') > 0:
            print "Network: " + astring
        elif (astring.find('$') > 0) or (astring.find('#') > 0) :
            print "CmdLine: " + astring
        elif len(astring) == 0:
            print "NilLine:" + astring
        else :
            print "IpRoute: " + astring
            ip_route_list = astring.split(" ")
            new_gw = ip_route_list[2]
            single_ip = ip_route_list[0]
            ip_network = single_ip[0:single_ip.rfind('.')]+'.0/24'
            found = False
            for (aip, gw) in single_ip_route:
                if aip == single_ip:
                    found = True
                    break
            if not found:
                run_cmd(del_route_fmt%astring, run)
                run_cmd_num += 1

    for (ip_network, gw, interface) in new_net_route:
        run_cmd(add_route_fmt%(ip_network, gw), run)
        run_cmd_num += 1
    return run_cmd_num
def sep_string_2layer(output, run, new_gw, new_gw_interface):
    '''The func change route on ouput of route table for 2layer network. 
    Net gateway with zone router, which traffic go net gateway to route'''
    alist = output.split('\n')
    have_users_route = False
    run_cmd_num = 0

# must add users route first, or sudo will fail after change the default route and sudo can not connect name server, it can not resolve the hostname.
    if output.find(users_network) < 0:
        add_users_route(run)
        run_cmd_num += 1
    for astring in alist:
        if astring.find('default') >= 0 :
            print "Default: " + astring
            if len(new_gw) > 0 :
                if astring.find(new_gw) < 0:
                    run_cmd(change_gw_fmt%(new_gw, new_gw_interface), run)
                    run_cmd_num += 1
            else :
                print "No new_gw. Do not chanage default gateway."

        elif astring.find('/') > 0:
            print "Network: " + astring
        elif (astring.find('$') > 0) or (astring.find('#') > 0) :
            print "CmdLine: " + astring
        elif len(astring) == 0:
            print "NilLine:" + astring
        else :
            print "IpRoute: " + astring
            run_cmd(del_route_fmt%astring, run)
            run_cmd_num += 1

    return run_cmd_num
def test_sep_string():
    ''' The func test analysis_gw().'''
    output1 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.78 
172.16.1.0/24 dev eth4  proto kernel  scope link  src 172.16.1.3 
172.16.2.0/24 dev eth5  proto kernel  scope link  src 172.16.2.2 
172.16.3.2 via 172.16.2.3 dev eth5 
172.16.3.3 via 172.16.2.4 dev eth5 
172.16.3.4 via 172.16.2.4 dev eth5 
172.16.4.2 via 172.16.2.4 dev eth5 
172.16.4.3 via 172.16.2.4 dev eth5 
172.16.4.4 via 172.16.2.4 dev eth5 
172.16.4.5 via 172.16.2.4 dev eth5 
172.16.4.9 via 172.16.2.4 dev eth5 
172.16.5.2 via 172.16.1.2 dev eth4 
172.16.5.3 via 172.16.1.2 dev eth4 
172.16.5.4 via 172.16.1.2 dev eth4 
172.16.5.10 via 172.16.1.2 dev eth4 
'''
    route2 = """default via 10.16.0.1 dev eth0
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.41
172.16.1.0/24 dev eth4  proto kernel  scope link  src 172.16.1.2
172.16.2.2 via 172.16.1.3 dev eth4
172.16.2.3 via 172.16.1.3 dev eth4
172.16.3.2 via 172.16.1.3 dev eth4
172.16.3.3 via 172.16.1.3 dev eth4
172.16.3.4 via 172.16.1.3 dev eth4
172.16.3.5 via 172.16.1.3 dev eth4
172.16.4.2 via 172.16.1.3 dev eth4
172.16.4.3 via 172.16.1.3 dev eth4
172.16.4.4 via 172.16.1.3 dev eth4
172.16.4.5 via 172.16.1.3 dev eth4
172.16.4.6 via 172.16.1.3 dev eth4
172.16.5.2 via 172.16.1.3 dev eth4
172.16.5.3 via 172.16.1.3 dev eth4
"""
    
    (new_gw, new_gw_interface, single_ip_route, new_net_route) = analysis_gw(output1)
    #"172.16.2.4", "eth5", [("172.16.3.2", "172.16.2.3")], [("172.16.5.0/24").network, "172.16.1.2", "eth4")]
    assert sep_string(output1, False, new_gw, new_gw_interface, single_ip_route, new_net_route) == 14
    (new_gw, new_gw_interface, single_ip_route, new_net_route) = analysis_gw(route2)
    assert sep_string(route2, False, new_gw, new_gw_interface, single_ip_route, new_net_route) == 15

def have_users_network(output):
    return output.find(users_network) >= 0

def is_gateway(output, ip):
    '''The func analysis if this machine is gateway. If this machine is gateway,
    its route output's local ip in network route line has the 
    gateway IP.
    '''
    alist = output.split('\n')
    last_subnet = ''

    for astring in alist:
        if astring.find('default') >= 0 :
            #print "Default: " + astring
            pass
        elif astring.find('/') > 0:
            #print "Network: " + astring
            ip_route_list = astring.split()
            #print "[%s]Localip [%s]"%(str(ip_route_list),"")
            if len(ip_route_list)>8:
                # local net card's subnet route have the local ip. such as:
                # 10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.79 
                # Some manual added route only have less segments.
                # 172.16.1.0/24 via 172.16.20.10 dev eth4 
                local_ip = ip_route_list[8]
                #print "[%s]Localip [%s]"%(str(ip_route_list),local_ip)
                if local_ip == ip:
                    return True
        elif (astring.find('$') > 0) or (astring.find('#') > 0) :
            #print "CmdLine: " + astring
            pass
        elif len(astring) == 0:
            #print "NilLine:" + astring
            pass
        else :
            #print "IpRoute: " + astring
            pass

    return False
def test_is_gateway():
    output1 = ''' lqun4583@n5:~$ ip route show
default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.79 
172.16.1.2 via 172.16.2.2 dev eth4 
172.16.1.3 via 172.16.2.2 dev eth4 
172.16.2.0/24 dev eth4  proto kernel  scope link  src 172.16.2.4 
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.3 
172.16.4.2 via 172.16.3.4 dev eth5 
172.16.4.3 via 172.16.3.4 dev eth5 
172.16.4.4 via 172.16.3.4 dev eth5 
172.16.4.5 via 172.16.3.4 dev eth5 
172.16.4.9 via 172.16.3.4 dev eth5 
172.16.5.2 via 172.16.2.2 dev eth4 
172.16.5.3 via 172.16.2.2 dev eth4 
172.16.5.4 via 172.16.2.2 dev eth4 
172.16.5.10 via 172.16.2.2 dev eth4 
'''
    output2 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.123 
172.16.1.2 via 172.16.3.3 dev eth5 
172.16.1.3 via 172.16.3.3 dev eth5 
172.16.2.2 via 172.16.3.3 dev eth5 
172.16.2.3 via 172.16.3.2 dev eth5 
172.16.2.4 via 172.16.3.3 dev eth5 
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.4 
172.16.4.0/24 dev eth4  proto kernel  scope link  src 172.16.4.2 
172.16.5.2 via 172.16.3.3 dev eth5 
172.16.5.3 via 172.16.3.3 dev eth5 
172.16.5.4 via 172.16.3.3 dev eth5 
172.16.5.10 via 172.16.3.3 dev eth5 
'''
    output3 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.143 
172.16.1.0/24 via 172.16.20.10 dev eth4 
172.16.2.0/24 via 172.16.20.20 dev eth4 
172.16.3.0/24 via 172.16.20.30 dev eth4 
172.16.4.0/24 via 172.16.20.40 dev eth4 
172.16.20.0/24 dev eth4  proto kernel  scope link  src 172.16.20.100
'''
    assert is_gateway(output1, "172.16.3.4") == False
    assert is_gateway(output2, "172.16.3.4") == True
    assert is_gateway(output3, "172.16.20.100") == True
    
CMD_CHECK_NAT2INTERNET = "sudo iptables -t nat -C POSTROUTING -o %s -j MASQUERADE "
CMD_NAT2INTERNET = "sudo iptables -t nat -A POSTROUTING -o %s -j MASQUERADE "

def sep_string_firewall(output, run):
    alist = output.split('\n')
    run_cmd_num = 0
    last_subnet = ''

    for astring in alist:
        if astring.find('default') >= 0 :
            print "Default: " + astring
            # setup the fw to access the internet.
            # default via 10.16.0.1 dev eth0
            words = astring.split()
            ip = words[2]
            interface = words[4]
            logging.getLogger(LOG_ENTITY).info("For gateway, add NAT to internet...")
            if subprocess.call(CMD_CHECK_NAT2INTERNET % interface, shell=True) != 0:
                # not added return 1, already added return 0.
                run_cmd(CMD_NAT2INTERNET % (interface), run)
                run_cmd_num += 1
            else:
                logging.getLogger(LOG_ENTITY).debug("Already added NAT ipatables rule.")
        elif astring.find('/') > 0:
            print "Network: " + astring
        elif (astring.find('$') > 0) or (astring.find('#') > 0) :
            print "CmdLine: " + astring
        elif len(astring) == 0:
            print "NilLine:" + astring
        else :
            print "IpRoute: " + astring
            ip_route_list = astring.split(" ")
            subnet = ip_route_list[0][0:ip_route_list[0].rfind('.')]+'.0/24'
            subnet_gw = ip_route_list[2]
            if subnet != last_subnet :
                print "There is a new subnet[%s] gateway[%s], add subnet route"%(subnet, subnet_gw)
                run_cmd(add_route_fmt%(subnet, subnet_gw), run)
                last_subnet = subnet
                run_cmd_num += 1

            run_cmd(del_route_fmt%astring, run)
            run_cmd_num += 1

    return run_cmd_num

def change_ubuntu16_sourcelist():
    # Check whether already changed?
    import shutil
    logging.getLogger(LOG_ENTITY).info('change_ubuntu16_sourcelist...')
    with open("/etc/apt/sources.list") as f:
        file_content = f.read()
    if file_content.find("\ndeb http://archive.ubuntu.com/ubuntu") != -1:
        logging.getLogger(LOG_ENTITY).info("Finded 'deb http://archive.ubuntu.com/ubuntu', Already changed and return.")
        return
    #os.rename("/etc/apt/sources.list", "/etc/apt/sources.list.orig")
    run_cmd("sudo mv /etc/apt/sources.list /etc/apt/sources.list.orig", True)
    #shutil.copyfile("/share/ven/ubuntu16.sources.list", "/etc/apt/sources.list")
    run_cmd('''sudo /share/ven/bin/update_file.py file "/share/ven/bin/source.list" "/etc/apt/sources.list" ''', True)
    logging.getLogger(LOG_ENTITY).info("Done")

def test_sep_string_firewall():
    route1 = """default via 10.16.0.1 dev eth0
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.105
172.16.1.2 via 172.16.3.3 dev eth5
172.16.1.3 via 172.16.3.3 dev eth5
172.16.2.2 via 172.16.3.4 dev eth5
172.16.2.3 via 172.16.3.4 dev eth5
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.5
172.16.4.0/24 dev eth4  proto kernel  scope link  src 172.16.4.2
172.16.5.2 via 172.16.3.2 dev eth5
172.16.5.3 via 172.16.3.2 dev eth5
"""
    route2 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.79 
172.16.1.2 via 172.16.2.2 dev eth4 
172.16.1.3 via 172.16.2.2 dev eth4 
172.16.2.0/24 dev eth4  proto kernel  scope link  src 172.16.2.4 
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.3 
172.16.4.2 via 172.16.3.4 dev eth5 
172.16.4.3 via 172.16.3.4 dev eth5 
172.16.4.4 via 172.16.3.4 dev eth5 
172.16.4.5 via 172.16.3.4 dev eth5 
172.16.4.9 via 172.16.3.4 dev eth5 
172.16.5.2 via 172.16.2.2 dev eth4 
172.16.5.3 via 172.16.2.2 dev eth4 
172.16.5.4 via 172.16.2.2 dev eth4 
172.16.5.10 via 172.16.2.2 dev eth4 
'''
    route3 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.123 
172.16.1.2 via 172.16.3.3 dev eth5 
172.16.1.3 via 172.16.3.3 dev eth5 
172.16.2.2 via 172.16.3.3 dev eth5 
172.16.2.3 via 172.16.3.2 dev eth5 
172.16.2.4 via 172.16.3.3 dev eth5 
172.16.3.0/24 dev eth5  proto kernel  scope link  src 172.16.3.4 
172.16.4.0/24 dev eth4  proto kernel  scope link  src 172.16.4.2 
172.16.5.2 via 172.16.3.3 dev eth5 
172.16.5.3 via 172.16.3.3 dev eth5 
172.16.5.4 via 172.16.3.3 dev eth5 
172.16.5.10 via 172.16.3.3 dev eth5 '''
    sep_string_firewall(route1, False)
    print sep_string_firewall(route3, False)
    assert sep_string_firewall(route3, False) == 13
    analysis_gw(route1)
    new_gw = "172.16.3.4" # IP
    new_gw_interface = "eth5" # "eth4"
    (new_gw, new_gw_interface, single_ip_route, new_net_route) = analysis_gw(route2, new_gw, new_gw_interface)
    assert (new_gw, new_gw_interface, single_ip_route, new_net_route) ==\
        ("172.16.3.4", "eth5", [], [("172.16.5.0/24", "172.16.2.2", "eth4"),
        ("172.16.1.0/24", "172.16.2.2", "eth4")])
    route4 = '''default via 10.16.0.1 dev eth0 
10.16.0.0/22 dev eth0  proto kernel  scope link  src 10.16.0.105 
172.16.1.0/24 via 172.16.20.1 dev eth4 
172.16.2.0/24 via 172.16.20.3 dev eth4 
172.16.3.0/24 via 172.16.20.5 dev eth4 
172.16.10.0/24 dev eth5  proto kernel  scope link  src 172.16.10.100 
172.16.20.0/24 dev eth4  proto kernel  scope link  src 172.16.20.100 

'''
    print sep_string_firewall(route4, False)


# The scipt default put in /share/ven/scripts/
# The log defualt put in home dir/hostname/chNetwork.log
if os.name == 'nt':
    log_dir = '.'
else:
    from os.path import expanduser
    home = '/proj' 
    import platform
    hostname = platform.node()
    names = hostname.split('.')
    if len(names) > 2:
        # get the first dir name under /proj.
        team_name = os.listdir(home)[0]
        log_dir = os.path.join(home, team_name, 'logs', hostname)
    else:
        # get the first dir name under /proj.
        team_name = os.listdir(home)[0]
        log_dir = os.path.join('/var/log/', hostname)

    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(name)-8s %(levelname)-6s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    filename=os.path.join(log_dir, "chNetwork.log"))
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s %(name)-8s %(levelname)-6s %(message)s')
ch.setFormatter(formatter)
# add the handlers to logger
logging.getLogger(LOG_ENTITY).addHandler(ch)

'''
if not interactive:
# if we run it from crontab, the route table only have 2item at the begining.
# we wait the deter change the route table, then chang it.
    run_cmd_num = 0
    while run_cmd_num == 0:
        run_cmd_num = sep_string_firewall(output, False)
        print "run_cmd_num:%d"%run_cmd_num
        if run_cmd_num == 0:
            time.sleep(300)
            '''
single_ip_route = []
new_net_route = []
if (len(sys.argv) == 2) and (sys.argv[1] == "test"):
    test_sep_string()
    test_sep_string_firewall()
    test_is_gateway()
    test_analysis_gw()
    logging.getLogger(LOG_ENTITY).info("Pass all test")
    exit()

# Update the ubuntu16 source.list.
#change_ubuntu16_sourcelist()
if len(sys.argv) == 2:
    if sys.argv[1] == 'source':
        change_ubuntu16_sourcelist()
        exit()

output = get_route()
logging.getLogger(LOG_ENTITY).info("Route:[%s]", output)
#sys.stdout = open('/tmp/abc.log', 'w')
#print 'test'
# May setup error default gateway ip. these reenter protection is not suit.
if have_users_network(output) :
    logging.getLogger(LOG_ENTITY).info("Already have users network route, have changed route before. Done")
    exit()
if (len(sys.argv) == 3) and (sys.argv[1] == "ssh"):
    # setup ssh after vagrant up.
    pass

if (len(sys.argv) == 2) and (sys.argv[1] == "firewall"):
    # For firewall we can
    if interactive :
        run_cmd_num = sep_string_firewall(output, False)
        if run_cmd_num > 0:
            print "Are you sure to run ?(y/n)"
            c = sys.stdin.read(1)
            if c == 'y' or c == 'Y' :
                sep_string_firewall(output, True)
        else :
            print "Nothing to change"
    else:
        '''
        run_cmd_num = 0
        while run_cmd_num == 0:
            run_cmd_num = sep_string_firewall(output, False)
            print "run_cmd_num:%d"%run_cmd_num
            if run_cmd_num == 0:
                time.sleep(300)
                '''
        sep_string_firewall(output, True)
    exit()
elif len(sys.argv) == 2:
    # for give gateway ip.
    if not sys.argv[1].find('.'):
        print("The parameter should be IP address.")
        usage()
        exit()
    i = 0
    while i < 100:
        output = get_route() #run_cmd("ip route show", True)
        if output != '':
            (new_gw, new_gw_interface) = analysis_gw_netgw(output, sys.argv[1])
            if new_gw != '':
                break
        logging.getLogger(LOG_ENTITY).info("Get route[%s], network is not ready, wait 10s" % output)
        time.sleep(10)
    if is_gateway(output, sys.argv[1]):
        if interactive :
            run_cmd_num = sep_string_firewall(output, False)
            if run_cmd_num > 0:
                print "Are you sure to run ?(y/n)"
                c = sys.stdin.read(1)
                if c == 'y' or c == 'Y' :
                    sep_string_firewall(output, True)
            else :
                print "Nothing to change"
        else:
            '''
            run_cmd_num = 0
            while run_cmd_num == 0:
                run_cmd_num = sep_string_firewall(output, False)
                print "run_cmd_num:%d"%run_cmd_num
                if run_cmd_num == 0:
                    time.sleep(300)
                    '''
            sep_string_firewall(output, True)
        output = get_route()
        logging.getLogger(LOG_ENTITY).info("Changed as gateway. Route:[%s]", output)
        exit()
    else:
        if NET2LAYER:
            (new_gw, new_gw_interface) = analysis_gw_netgw(output, sys.argv[1])
        else:
            (new_gw, new_gw_interface, single_ip_route, new_net_route) = analysis_gw(output, "", "", sys.argv[1])
    
#elif len(sys.argv) == 1:
    # Leaf node could self learn the default gateway.
    # if wrongly use it on router, it will use the last gateway as the default gateway.
    #(new_gw, new_gw_interface, single_ip_route, new_net_route) = analysis_gw(output)
    
elif (len(sys.argv) == 4) and (sys.argv[1] == 'router'):
    new_gw = sys.argv[2] # IP
    new_gw_interface = sys.argv[3] # "eth4"
    (new_gw, new_gw_interface, single_ip_route, new_net_route) = analysis_gw(output, new_gw, new_gw_interface)
else:
    usage()
    exit()

if interactive:
    if NET2LAYER:
        run_cmd_num = sep_string_2layer(output, False, new_gw, new_gw_interface)
    else:
        run_cmd_num = sep_string(output, False, new_gw, new_gw_interface, single_ip_route, new_net_route)
    if run_cmd_num > 0:
        print "Are you sure to run ?(y/n)"
        c = sys.stdin.read(1)
        if c == 'y' or c == 'Y' :
            sep_string(output, True, new_gw, new_gw_interface, single_ip_route, new_net_route)
    else :
        print "Nothing to change"
else:
    if NET2LAYER:
        sep_string_2layer(output, True, new_gw, new_gw_interface)
    else:
        sep_string(output, True, new_gw, new_gw_interface, single_ip_route, new_net_route)
output = get_route()
logging.getLogger(LOG_ENTITY).info("Changed. Route:[%s]", output)

#=============================================================================
# Test code



#test_sep_string_firewall()

