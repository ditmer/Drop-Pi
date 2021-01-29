Hostpad configuration for pi


```sh
apt-get install hostapd dnsmasq
```

Edit these files:

```sh
/etc/hostapd/hostapd.conf
/etc/dnsmasq.conf
/etc/network/interfaces
```

On Kali (2019.3 ARM) you need to unmask hostapd
```
systemctl unmask hostapd
```


Start services
```
systemctl start hostapd
systemctl start dnsmasq

systemctl enable hostapd
systemctl enable dnsmasq
```
