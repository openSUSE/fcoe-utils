###############################################################################
#
# fcoe_debug: print debugging information for fcoe
#         $1: interface
###############################################################################

if [ -z $1 ]; then
    echo "Usage: `basename $0` eth[0-9]"
    exit 1;
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
	echo -e "\n###Adapter INFO"
	echo -e "#ethtool:"
	ethtool $1
	echo -e "#ethtool interface:"
	ethtool -i $1
	echo -e "#ethtool pause:"
	ethtool -a $1
	echo -e "#ethtool offloads:"
	ethtool -k $1
	echo -e "#ethtool stats:"
	ethtool -S $1
	echo -e "#ifconfig:"
	ifconfig $1
}

dcb_info () {
	echo -e "\n###DCB INFO"
	echo -e "#tc config"
	tc qdisc
	tc filter show dev $1
	echo -e "#service dcbd status:"
	service dcbd status
	echo -e "\n########## Showing dcb for $1"
	dcbtool -v
	dcbtool gc $1 dcb
	echo -e "\n########## Getting dcb config for $1"
	dcbtool gc $1 pg
	echo
	dcbtool gc $1 pfc
	echo
	dcbtool gc $1 app:0
	echo
	dcbtool gc $1 ll:0
	echo -e "\n########## Getting dcb oper for $1"
	dcbtool go $1 pg
	echo
	dcbtool go $1 pfc
	echo
	dcbtool go $1 app:0
	echo
	dcbtool go $1 ll:0
	echo -e "\n########## Getting dcb peer for $1"
	dcbtool gp $1 pg
	echo
	dcbtool gp $1 pfc
	echo
	dcbtool gp $1 app:0
	echo
	dcbtool gp $1 ll:0
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
	kernel_info $1
	system_info $1
	adapter_info $1
	dcb_info $1
	fcoe_info $1
	sysfs_dump $1
	logfile_dump
}

fcoe_debug $1


