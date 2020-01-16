#!/usr/bin/env python

import os
import sys


def node_proc(hosts_txt):
    '''
    loop through the hosts list to complete ping test
    :param hosts_txt: the path to hosts.txt
    :return:

    '''
    tested = []
    with open(hosts_txt, 'r') as afile:
        lines = afile.read().splitlines()
    for line in lines:
        info = line.split(',')
        host = info[0]
        if tested.index(host) > -1:
            continue
        tested.append(host)
        test_host(host, hosts_txt)


def test_host(hosts_txt):
    '''
    on given host, to loop through the hosts.txt to complete ping test
    :param hosts_txt: the path to hosts.txt
    :return:
    '''
    failure_target = []
    with open(hosts_txt, 'r') as afile:
        lines = afile.read().splitlines()
    for line in lines:
        info = line.split(',')
        target_host = info[0]
        target_ip = info[1]
#        if target_host == host:
#            continue
        result = ping(target_ip)
        if result > 1 and target_host not in failure_target:
            failure_target.append(target_host)
        elif result == 0 and target_host in failure_target:
            failure_target.remove(target_host)
        print "target: %s result: %s" % (target_ip, result)
    print "failed to ping %s" % (failure_target)


def ping(hostname):
    return os.system("ping -c 1 " + hostname)


def test_ping():
    assert ping("google.com") == 0
    assert ping("127.0.0.1") == 0


def test():
    test_ping()


'''
no way to access /ahare/ven/bin/nodetest.py in VM
'''
def main():
    if (len(sys.argv) == 2) and (sys.argv[1] == "test"):
        test()
        print "Pass all test"
        exit()
    elif (len(sys.argv) == 1):
        hosts_txt = "/vagrant/hosts.txt"
        test_host(hosts_txt)


if __name__ == "__main__":
    main()

