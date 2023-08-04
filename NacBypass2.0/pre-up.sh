#!/bin/bash

ifconfig wlan0 down
systemctl disable NetworkManager
systemctl stop NetworkManager
