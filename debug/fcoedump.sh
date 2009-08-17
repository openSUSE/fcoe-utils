###############################################################################
#
# fcoe_debug: print debugging information for fcoe
#         $1: interface
###############################################################################

if [ -z $1 ]; then
    echo "Usage: `basename $0` eth[0-9]"
    exit 1;
fi

DEVICE=$1

if [ -r /proc/net/vlan/$DEVICE ] ; then
	PHYSDEV=$(grep '^Device:' /proc/net/vlan/$DEVICE | awk '{print $2}')
else
	PHYSDEV=$DEVICE
fi

kernel_info () {
	echo -e "\n###KERNEL INFO###"
	uname -a
}

system_info () {
	echo -e "\n###System Info###"
	echo -e "#lsscsi:"
	lsscsi
	echo -e "#lspci:"
	lspci

	echo -e "#check symbols:"
	grep dcbnl_init /proc/kallsyms
	grep fcoe /proc/kallsyms
}

adapter_info () {
	if [ $DEVICE != $PHYSDEV ]
	then
		echo -e "\n###Adapter INFO VLAN $DEVICE"
		echo -e "#ethtool:"
		ethtool $DEVICE
		echo -e "#ethtool interface:"
		ethtool -i $DEVICE
		echo -e "#ethtool offloads:"
		ethtool -k $DEVICE
		echo -e "#ifconfig:"
		ifconfig $DEVICE
	fi

	echo -e "\n###Adapter INFO $PHYSDEV"
	echo -e "#ethtool:"
	ethtool $PHYSDEV
	echo -e "#ethtool interface:"
	ethtool -i $PHYSDEV
	echo -e "#ethtool pause:"
	ethtool -a $PHYSDEV
	echo -e "#ethtool offloads:"
	ethtool -k $PHYSDEV
	echo -e "#ethtool stats:"
	ethtool -S $PHYSDEV
	echo -e "#ifconfig:"
	ifconfig $PHYSDEV
}

dcb_info () {
	echo -e "\n###DCB INFO"
	echo -e "#tc config"
	tc qdisc
	tc filter show dev $PHYSDEV | grep -v filter
	echo -e "#service dcbd status:"
	service dcbd status
	echo -e "\n########## Showing dcb for $PHYSDEV"
	dcbtool -v
	dcbtool gc $PHYSDEV dcb
	echo -e "\n########## Getting dcb config for $PHYSDEV"
	dcbtool gc $PHYSDEV pg
	echo
	dcbtool gc $PHYSDEV pfc
	echo
	dcbtool gc $PHYSDEV app:0
	echo
	dcbtool gc $PHYSDEV ll:0
	echo -e "\n########## Getting dcb oper for $PHYSDEV"
	dcbtool go $PHYSDEV pg
	echo
	dcbtool go $PHYSDEV pfc
	echo
	dcbtool go $PHYSDEV app:0
	echo
	dcbtool go $PHYSDEV ll:0
	echo -e "\n########## Getting dcb peer for $PHYSDEV"
	dcbtool gp $PHYSDEV pg
	echo
	dcbtool gp $PHYSDEV pfc
	echo
	dcbtool gp $PHYSDEV app:0
	echo
	dcbtool gp $PHYSDEV ll:0
}

fcoe_info () {
	echo -e "\n###FCOE Info"
	echo -e "#service fcoe status"
	service fcoe status
	echo -e "#fcoeadm output "
	fcoeadm -v
	echo -e "#fcoeadm -i "
	fcoeadm -i
	echo -e "#fcoeadm -t "
	fcoeadm -t
}

sysfs_dump () {
	echo -e "###SYSFS dump"
	echo -e "#sysfs fc_host dump"
	find /sys/class/fc_host/host*/ -type f -print -exec cat '{}' \;
	echo -e "#sysfs fc_transport dump"
	find /sys/class/fc_transport/target*/ -type f -print -exec cat '{}' \;
	echo -e "#sysfs fc_remote_ports dump"
	find /sys/class/fc_remote_ports/*/ -type f -print -exec cat '{}' \;
	echo -e "#sysfs fc_vport dump"
	find /sys/class/fc_vports/*/ -type f -print -exec cat '{}' \;
}

logfile_dump() {
	echo "###LOGFILES"
	echo "#/var/log/messages"
	cat /var/log/messages
	echo
	echo "#dmesg"
	dmesg
}

fcoe_debug () {
	kernel_info
	system_info
	adapter_info
	dcb_info
	fcoe_info
	sysfs_dump
	logfile_dump
}

fcoe_debug


