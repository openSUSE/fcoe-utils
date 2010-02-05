#!/bin/bash

# Script to read EDD information from sysfs and
# echo the FCoE interface name and target info.
# This is a work in progress and will be enhanced
# with more options as we progress further.
#
# Author: Supreeth Venkataraman
#         Intel Corporation
#
# Usage: edd.sh -i for getting the interface name.
#        edd.sh -t for getting target information.
#        edd.sh -h for displaying help information.

DisplayHelp(){
  echo "Usage: sysfs_edd.sh -i for getting the interface name."
  echo "       sysfs_edd.sh -t for getting target information."
  echo "       sysfs_edd.sh -h for displaying help options."
  exit;
}

GetTargetInfo(){
   if [ -e /sys/firmware/edd/int13_dev80/interface ]; then
      cd -P /sys/firmware/edd/int13_dev80
   else
      echo "Target information not found in EDD!"; exit;
   fi

   line=`cat interface`;
   echo $line;
}


GetFcoeIfName(){
   if [ -e /sys/firmware/edd/int13_dev80/pci_dev ]; then
        cd -P /sys/firmware/edd/int13_dev80/pci_dev
   else
      echo "Disk 80 not found in EDD!"; exit;
   fi

   for if in net/eth* ;
   do [ -d $if ] && echo ${if##*/}; done
}

while getopts ith OptionName; do
    case "$OptionName" in
        t) GetTargetInfo;;
        i) GetFcoeIfName;;
        h) DisplayHelp;;
        *) echo "Invalid Option. Use -h option for help.";;
    esac
done
