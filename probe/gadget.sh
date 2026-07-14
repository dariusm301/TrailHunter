#!/bin/bash

#cleanup
echo "" > /sys/kernel/config/usb_gadget/trailhunter/UDC 2>/dev/null || true
rm -f /sys/kernel/config/usb_gadget/trailhunter/configs/c.1/rndis.usb0
rm -f /sys/kernel/config/usb_gadget/trailhunter/configs/c.1/hid.usb0

modprobe libcomposite

mkdir -p /sys/kernel/config/usb_gadget/trailhunter
cd /sys/kernel/config/usb_gadget/trailhunter

echo 0x1d6b > idVendor
echo 0x0104 > idProduct
echo 0x0100 > bcdDevice
echo 0x0200 > bcdUSB

mkdir -p strings/0x409
echo "TH001" > strings/0x409/serialnumber
echo "DM" > strings/0x409/manufacturer
echo "TrailHunter collector" > strings/0x409/product

mkdir -p configs/c.1/strings/0x409
echo "Config 1: RNDIS network" > configs/c.1/strings/0x409/configuration
echo 250 > configs/c.1/MaxPower

# --- NCM for ethernet ---
mkdir -p functions/ncm.usb0
echo "02:22:33:44:55:66" > functions/ncm.usb0/host_addr
echo "12:22:33:44:55:66" > functions/ncm.usb0/host_addr
ln -s functions/ncm.usb0 configs/c.1/

# --- HID keyboard ---
mkdir -p functions/hid.usb0
echo 1 > functions/hid.usb0/protocol    # 1 = Keyboard
echo 1 > functions/hid.usb0/subclass    # 1 = Boot Interface
echo 8 > functions/hid.usb0/report_length  # 8 bytes per report
echo -ne \
'\x05\x01\x09\x06\xa1\x01\x05\x07\x19\xe0\x29\xe7\x15\x00\x25\x01'\
'\x75\x01\x95\x08\x81\x02\x95\x01\x75\x08\x81\x03\x95\x06\x75\x08'\
'\x15\x00\x25\x65\x05\x07\x19\x00\x29\x65\x81\x00\xc0' \
> functions/hid.usb0/report_desc
ln -s functions/hid.usb0 configs/c.1/

# --- Bind ---
ls /sys/class/udc > UDC

sleep 1

ifconfig usb0 172.16.0.1 netmask 255.255.255.0 up
