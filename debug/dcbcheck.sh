#!/bin/bash
# $1 = ethX
# return 0 on success
# return 1 on failure

IFNAME=$1
ret=0

# check for DCB netlink symbols
if ! grep -q "\bdcbnl_init\b" /proc/kallsyms ; then
    echo "DCB Netlink symbols not found in the kernel." >&2
    echo "Please re-compile the kernel with CONFIG_DCB=y." >&2
    exit 1
fi

# Ensure that a value was passed in for the interface name
if [ "${IFNAME}" == "" ] ; then
    echo "Please provide the interface name to check." >&2
    exit 1
fi

# Ensure that the interface name provided is valid
if ifconfig ${IFNAME} 2>&1 | grep -q "Device not found" ; then
    echo "Please provide a valid interface name." >&2
    exit 1
fi

# Determine if we can communicate with DCBD
if dcbtool gc ${IFNAME} dcb | grep Status | grep -q Failed ; then
    echo "Unable to communicate with the DCB daemon (dcbd) or DCB capable driver." >&2
    exit 1
fi

# Determine if DCB is on
if dcbtool gc ${IFNAME} dcb | grep 'DCB State' | grep -q off ; then
    echo "DCB is not on, execute the following command to turn it on" >&2
    echo "dcbtool sc ${IFNAME} dcb on" >&2
    ret=1
fi

# Determine if PFC is enabled
if dcbtool gc ${IFNAME} pfc | grep Enable | grep -q false ; then
    echo "PFC is not enabled, execute the following command to turn it on" >&2
    echo "dcbtool sc ${IFNAME} pfc e:1" >&2
    ret=1
fi

# Determine if the FCoE APP TLV is enabled
if dcbtool gc ${IFNAME} app:fcoe | grep Enable | grep -q false ; then
    echo "The FCoE APP TLV is not enabled, execute the following command to turn it on" >&2
    echo "dcbtool sc ${IFNAME} app:fcoe e:1" >&2
    ret=1
fi

if [ ${ret} -eq 0 ] ; then
    echo "DCB is correctly configured for FCoE"
fi

exit ${ret}
