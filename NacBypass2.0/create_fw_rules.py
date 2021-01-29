#!/usr/bin/python3

import argparse
import socket
import os


if __name__ == '__main__':
    if os.getuid() != 0:
        exit("Root privileges are needed. Try again with sudo....or just don't. K, Bye.")

    tool_list = [
        'custom',
        'responder'
    ]

    actions = {
        'up': '-A',
        'down': '-D'
    }

    parser = argparse.ArgumentParser(description='Create firewall rules for local tools. Prerouting rules to take traffic from bridge and send it to Pi.\
     Example: ./create_fw_rules.py -t custom -cip 10.0.1.1 -bip 169.254.66.66 -bint br0 -p 80 443 2233 -a up')
    parser.add_argument('-t', '--type', choices=tool_list, help='Specifc tools to build firewall rules for, or create custom rules', required=True)
    parser.add_argument('-cip', '--compIP', help='IP address of Pi and victim machine. HINT: They are the same.', required=True)
    parser.add_argument('-bip', '--bridgeIP', help='IP address of bridge', default='169.254.66.66')
    parser.add_argument('-bint', '--brint', help='Bridge interface', default='br0')
    parser.add_argument('-p', '--port', nargs='+', type=int, help='List of ports to create firwall rules for, can be one or more ports: -p 80 443 8443')
    parser.add_argument('-a', '--action', choices=['up', 'down'], help='Create or tear down specific rule sets', required=True)
    args = parser.parse_args()

    ports = {
        'custom': {'port_list': args.port, 'help': 'custom rule created'},
        'responder': {'port_list': [53, 88, 137, 138, 389, 445, 5353, 5355, 5553], 'help': 'Run "responder -I {0} -e {1}" to get started'.format(args.brint, args.compIP)}
    }
    try:
        socket.inet_aton(args.bridgeIP)
        socket.inet_aton(args.compIP)
    except:
        #print('Invalid IP')
        exit('Invalid IP')

    amIdone = True
    for port in ports[args.type]['port_list']:
        if args.brint in os.listdir('/sys/class/net/'):
            print('Bringing {} iptables PREROUTING rule for tcp/udp port: {}'.format(args.action, port))
            #iptables -t nat -A PREROUTING -i $BRINT -d $COMPIP -p udp --dport 53 -j DNAT --to $BRIP:53
            fwcmd_tcp = 'iptables -t nat {0} PREROUTING -i {1} -d {2} -p tcp --dport {3} -j DNAT --to {4}:{3}'.format(actions[args.action], args.brint, args.compIP, port, args.bridgeIP)
            fwcmd_udp = 'iptables -t nat {0} PREROUTING -i {1} -d {2} -p udp --dport {3} -j DNAT --to {4}:{3}'.format(actions[args.action], args.brint, args.compIP, port, args.bridgeIP)
            try:
                os.system(fwcmd_tcp)
                os.system(fwcmd_udp)
                amIdone = True
            except:
                print('issuse creating rule for port: ', port)
                amIdone = False
                pass
    if amIdone and args.action == 'up':
        #print help messag for rule creation type
        print("Done!")
        print(ports[args.type]['help'])