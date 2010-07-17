#! /bin/bash
#
# Copyright 2008-2010 Cisco Systems, Inc.  All rights reserved.
#
# This program is free software; you may redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
# BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
# ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.
#
# Author: Joe Eykholt (jeykholt at cisco dot com)
#
# Please send comments and changes to jeykholt at cisco dot com

VERSION="fcc v1.0.11 06/18/2010"

fcoe_dir=/sys/module/fcoe
fdir=/sys/class/fc_host
sdir=/sys/class/scsi_host
cmdname=`basename $0`

usage() {
cat <<USAGE
usage: $cmdname '[<cmd> [<hba> ...]]'

cmd:
	create 		Start FCoE on an Ethernet interface.
	create-vn	Start FCoE (VN_port-VN_port) on an Ethernet interface.
	delete / del	Delete an FCoE instance
	destroy 	Same as delete
	enable / en	Same as create
	help		Show this usage message
	info		Show HBA detailed info
	list		List the HBAs with remote port and LUN status
	luns		Show LUN list and status
	scan		Scan the HBA
	stats		Show HBA statistics
	reload		Reload fcoe and fnic modules
	reset		Reset the HBA
	version		Show version
USAGE
}

verify_hba() {
	local x=$1

	if [ ! -d $fdir/$x ]
	then
		echo "$cmdname: invalid HBA name $x" >&2
		exit
	fi
}

hba_stats() {
	local x=$1
	local y

	verify_hba $x

	printf "\n$x Statistics:\n"
	(
		cd $fdir/$x/statistics
		for y in *
		do
			#
			# avoid the write-only files.
			# test -r doesn't help if we're root
			#
			if [ "$y" == "reset_statistics" ]
			then
				continue
			fi
			val=`cat $y`
			if [ "$val" != 0xffffffffffffffff ]
			then
				printf "%-30s%8lld\n" $y: $val
			fi
		done
	)
}


#
# format a /sys file containing a hex WWN or FC_ID
# from 0x123456\n to 12:34:56 or from 0xffffffff to - (unknown WWN or FC_ID)
#
fmt_hex() {
	sed -e 's/^0xff*$/-/' -e 's/0x//' -e 's/../&:/g' -e 's/:$//' < $1
}

rport_list() {
	local x
	local hba=$1

	rdir=/sys/class/fc_remote_ports
	host=`echo $hba | sed -e 's/host//'`
	rports=`ls -d $rdir/rport-$host:* 2>/dev/null`
	if [ -z "$rports" ]
	then
		return
	fi

	printf "\n$hba Remote Ports:\n"


	fmt="%-8s  %-23s  %-8s  %-8s  %-15s\n"

	printf "$fmt" Path "Port Name" "Port ID" State Roles
	for x in $rports
	do
		btl="`echo $x | sed -e 's/.*-\(.*-.*\)/\1/'`"
		printf "$fmt" "$btl" \
			"`fmt_hex $x/port_name`" \
			"`fmt_hex $x/port_id`" \
			"`cat $x/port_state`" \
			"`cat $x/roles`"
	done
}

#
# Translate capacity to readable units.
# compute sizes in base-10 marketing units
#
lun_cap() {
	local sizek=0 sizem=0 sizeg=0 sizet=0
	local size
	local onek=1000
	local cap

	size=$1
	let sizek="$size * 512 / $onek"
	let sizem="$sizek / $onek"
	let sizeg="$sizem / $onek"
	let sizet="$sizeg / $onek"
	if [ "$sizet" -gt 0 ]
	then
		cap="$sizet TB"
	elif [ "$sizeg" -gt 0 ]
	then
		cap="$sizeg GB"
	elif [ "$sizem" -gt 0 ]
	then
		cap="$sizem MB"
	else
		cap="$sizek KB"
	fi
	echo $cap
}

lun_list() {
	local x
	local lun
	local hba=$1
	local ddir=/sys/class/scsi_device

	host=`echo $hba | sed -e 's/host//'`

	local luns=`(cd $ddir &&
		 ls -d $host:* | sort -n -t: -k1 -k2 -k3 -k4) 2>/dev/null`

	if [ -z "$luns" ]
	then
		return
	fi

	printf "\n$hba LUNs:\n"

	fmt="%-10s %-8s %6s   %-15s %-20s %-8s\n"

	printf "$fmt" Path Device Size Vendor Model State

	for lun in $luns
	do
		(
			local size=0
			cap=-

			cd $ddir/$lun/device
			if [ -d block ]
			then
				dev=`ls block | tail -1`
				size=`cat block/$dev/size`
				cap=`lun_cap $size`
			elif [ -d char ]
			then
				dev=`ls char | tail -1`
				cap=-
			elif [ -d scsi_tape ]
			then
				dev=`ls scsi_tape | egrep '^st[0-9]*$'`
				cap=-
			elif [ -d scsi_generic ]
			then
				dev=`ls scsi_generic | tail -1`
				cap=-
			else
				dev="`ls -d block:* char:* 2>/dev/null |
					sed -e 's/.*\://'`"
				if [ -L block:$dev -o -d block:$dev ]
				then
					size=`cat block:$dev/size`
					cap=`lun_cap $size`
				fi
			fi

			printf "$fmt" "$lun" "$dev" "$cap"\
				"`cat vendor`" \
				"`cat model`" \
				"`cat state`"
		)
	 done
}

sym_name() {
	local hba=$1
	local file

	file=$fdir/$hba/symbolic_name
	if [ -f "$file" ]
	then
		sed -e 's/.*over //' < $file
	else
		exit 1
	fi
}

#
# Lookup the host name for a given symbolic name
#
hba_name() {
	local sym=$1
	local hba

	if [ -d "$fdir/$sym" ]
	then
		echo $sym
		exit
	fi

	for hba in $all_hbas
	do
		if [ "`sym_name $hba`" = "$sym" ]
		then
			echo $hba
			exit
		fi
	done
	exit 1
}

hba_state() {
	local x

	echo "FC HBAs:"
	fmt="%-8s  %-23s  %-8s  %-8s  %-15s\n"
	printf "$fmt" HBA "Port Name" "Port ID" State Device
	for x in $hbas
	do
		(
			cd $fdir/$x
			printf "$fmt" "$x" \
				"`fmt_hex $fdir/$x/port_name`" \
				"`fmt_hex $fdir/$x/port_id`" \
				"`cat $fdir/$x/port_state`" \
				"`sym_name $x`"
		) 2>/dev/null
	done
}

hba_info() {
	local x=`hba_name $1`
	local fmt="\t%-20s %s\n"

	verify_hba $x
	printf "\n$x Info:\n"
	(
		cd $fdir/$x

		printf "$fmt" "Symbolic Name" "`cat symbolic_name`"
		printf "$fmt" "Port Name" "`fmt_hex port_name`"
		printf "$fmt" "Node Name" "`fmt_hex node_name`"
		printf "$fmt" "Port Type" "`cat port_type`"
		echo
		printf "$fmt" "Port State" "`cat port_state`"
		printf "$fmt" "Port ID" "`fmt_hex port_id`"
		printf "$fmt" "Fabric Name" "`fmt_hex fabric_name`"
		echo
		printf "$fmt" "Max Frame Size" "`cat maxframe_size`"
		printf "$fmt" "Speed" "`cat speed`"
		echo
	)
}

scsi_state() {
	local x
	local dev

	printf "\nSCSI States:\n"
	fmt="%-8s  %-10s  %-15s  %-10s  %8s\n"
	printf "$fmt" HBA Device Mode State Busy
	for x in $scsi_hbas
	do
		(
			cd $fdir/$x
			dev="`cat $sdir/$x/proc_name``cat $sdir/$x/unique_id`"
			printf "$fmt" "$x" "$dev" \
				"`cat $sdir/$x/active_mode`" \
				"`cat $sdir/$x/state`" \
				"`cat $sdir/$x/host_busy`"
		) 2>/dev/null
	done
}

hba_list() {
	local x

	hba_state
	#  scsi_state

	for x in $hbas
	do
		rport_list $x
		lun_list $x
	done
}

#
# Do a command for a list of arguments
#
repeat() {
	local cmd=$1
	local x
	shift

	for x
	do
		$cmd $x
	done
}

fcoe_ctl() {
	local cmd=$1
	local hba=$2
	local file=$fcoe_dir/parameters/$cmd

	if [ -w "$file" ]
	then
		echo $hba > $file
	elif [ -f "$file" ]
	then
		echo "$cmdname: no permission to $cmd $hba" >&2
	else
		echo "$cmdname: file $file doesn't exist.  " \
			"Check for fcoe module." >&2
	fi
}

fc_host_ctl() {
	local hba=$2
	local host=$2
	local cmd=$1
	local value
	local file
	local dir

	dir=$fdir/$host
	if [ ! -d "$dir" ]
	then
		host=`hba_name $hba`
		dir=$fdir/$host
		if [ $? != 0 ]
		then
			echo "$cmdname: hba $hba not found" >&2
			exit 1
		fi
	fi

	case "$cmd" in
		reset)
			file=$dir/issue_lip
			value=1
		;;
		scan)
			file=$dir/device/scsi_host/$host/scan
			value="- - -"
	esac

	if [ -w "$file" ]
	then
		echo $value > $file
	elif [ -f "$file" ]
	then
		echo "$cmdname: no permission to $cmd $hba" 1>&2
		exit 2
	else
		echo "$cmdname: $cmd not supported for $hba" 1>&2
		exit 2
	fi
}

load_mod()
{
	if [ ! -d $fcoe_dir ]
	then
		modprobe fcoe
		echo "$cmdname: loading fcoe module" >&2
		sleep 1
		if [ ! -d $fcoe_dir ]
		then
			echo "$cmdname: $fcoe_dir not found" >&2
			exit 2
		fi
	fi
}

#
# Start of main script code.
#
scsi_hbas=
if [ -d "$sdir" ]
then
	scsi_hbas=`ls $sdir 2>/dev/null`
fi
if [ -d "$fdir" ]
then
	all_hbas=`ls $fdir 2>/dev/null`
fi
hbas="$all_hbas"

if [ $# -lt 1 ]
then
	hba_list
	exit 0
fi

if [ $# -lt 2 ]
then
	cmd=$1
	hba_spec=no
else
	cmd=$1
	hba=$2
	shift
	if [ $# -eq 0 ]
	then
		hba_spec=n
	elif [ $# -eq 1 -a "$1" = all ]
	then
		hba_spec=y
	else
		hba_spec=y
		hbas="$@"
		scsi_hbas="$@"
	fi
fi

hba_required()
{
	if [ "$hba_spec" != y ]
	then
		echo "$cmdname: $cmd requires HBA name" >&2
		exit 2
	fi
}

case "$cmd" in
	create | enable | en)
		hba_required
		load_mod
		repeat "fcoe_ctl create" $hbas
		;;
	create-vn)
		hba_required
		load_mod
		repeat "fcoe_ctl create_vn2vn" $hbas
		;;
	delete | del | destroy)
		if [ ! -d $fcoe_dir ]
		then
			echo "$cmdname: $fcoe_dir not found" >&2
			exit 2
		fi
		hba_required
		repeat "fcoe_ctl destroy" $hba
		;;
	info)
		repeat hba_info $hbas
		;;
	list)
		hba_list
		;;
	lun*)
		repeat lun_list $hbas
		;;
	names)
		repeat echo $hbas
		;;
	stat*)
		repeat hba_stats $hbas
		;;
	realname)
		hba_name $hba
		;;
	reload)
		mods=
		for mod in fcoe fnic
		do
			if [ -d /sys/module/$mod ]
			then
				mods="$mods $mod"
			fi
		done
		rmmod $mods libfcoe libfc
		modprobe $mods
		;;
	reset | scan)
		hba_required
		repeat "fc_host_ctl $cmd" $hbas
		;;
	version)
		echo $VERSION
		;;
	*)
		usage
		;;
esac
