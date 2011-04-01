#!/bin/bash
#
# fcoe-setup.sh
#
# Create VLAN interface for FCoE
#

scan_vlan() {
    local ifname=$1
    local vlan=$2

    cat /proc/net/vlan/config | tail +3 | while read vif s1 vid s2 if ; do
	if [ "$if" = "$ifname" ] && [ "$vid" == "$vlan" ] ; then
	    echo "$vif"
	fi
    done
}

create_vlan () {
    local ifname=$1
    local vlan=$2
    local vif

    vif=$(scan_vlan $ifname $vlan)

    if [ -z "$vif" ] ; then
        vif="$ifname.$vlan"
        ip link add dev $vif link $ifname type vlan id $vlan
    fi
    ip link set $vif up
    echo "$vif"
}

check_ifcfg () {
    local vif=$1
    local ifname=$2
    local vid=$3
    local ifcfg=/etc/sysconfig/network/ifcfg-$vif

    if [ -f "$ifcfg" ] ; then
	echo "Interface is configured properly"
    else
	echo "Creating ifcfg configuration ifcfg-$vif"
	cat > $ifcfg <<EOF
BOOTPROTO="static"
STARTMODE="onboot"
ETHERDEVICE="$ifname"
USERCONTROL="no"
INTERFACETYPE="vlan"
EOF
    fi
}

check_fcoe () {
    local vif=$1
    local fcoecfg=/etc/fcoe/cfg-$vif

    if [ -f "$fcoecfg" ] ; then
	echo "FCoE is configured properly"
    else
	echo "Creating FCoE configuration cfg-$vif"
	cat > $fcoecfg <<EOF
FCOE_ENABLE="yes"
DCB_REQUIRED="yes"
EOF
    fi
}

ifname=$1
if [ -z "$ifname" ] ; then
    echo "No Interface given!"
    exit 1
fi
if [ ! -d /sys/class/net/$ifname ] ; then
    echo "Interface $ifname does not exist!"
    exit 2
fi

fipvlan -i $ifname | while read ifname vlan; do
    echo "Found FCF forwarder on VLAN $vlan"
    vif=$(create_vlan $ifname $vlan)
    echo "Using VLAN interface $vif"
    check_ifcfg $vif $ifname $vlan
    check_fcoe $vif
done

exit 0
