Run with:
python eap_proxy.py <ONT_INTERFACE_NAME> <MODEM_INTERFACE_NAME>

Example: python eap_proxy.py eth0 eth1

This should run on an EdgerouterLite and many other devices without issue. You may need to restart dhcp for your ethernet device on your WAN to get this working(After it's proxied all the EAP packets the first time). You may need to create a vlan 0 on your ONT device to be your WAN, and you almost certainly have to clone the mac of your modem on the ONT device interface. I'm terrible at documentation, so good luck.

# eap_proxy.service
To run this script as a systemd service:

* Copy `eap_proxy.service` to `/etc/systemd/system/`
* run the commands `systemctl enable eap_proxy; systemctl start eap_proxy`
* Make sure you change the `YOUR_ONT` and `YOUR_INT` values to the correct iface names and that the `eap_proxy.service` file is calling the correct locations of this script and your python binary.

# Python3
This script has been ported to Python 3, but should still be compatible with earlier versions.
