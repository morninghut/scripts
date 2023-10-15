#!/bin/bash
#
# =================================================================
# INTRODUCTION:
#
# This script can find which Docker container the Python program
# that is currently occupying the GPU memory belongs to.
# =================================================================
# DETAIL:
#
# The script will filter out Python from the output of nvidia-smi,
# extract the PID, obtain the corresponding container ID
# from /proc/PID/cgroup, and then search
# for the corresponding container name in `docker ps`
# using the obtained container ID, and finally output it.
#
# The intermediate results during the running process
# will be temporarily saved in /tmp/t0.txt and t1.txt.
# After the running is completed, both files will be deleted.
# =================================================================

blue="\033[1;96m"
nocol="\033[0m"
red="\033[1;95m"
nvidia-smi | grep python | awk '$4 {print $5}' | awk ' !x[$0]++' >> /tmp/t0.txt
for line in `cat /tmp/t0.txt`
do
        echo  -n -e "$blue PID:$nocol"
        echo -e "$red $line $nocol"
        cat /proc/$line/cgroup | awk ' NR==1 ' | tr '/' ' ' | awk '$3 {print $3}' | cut -c 1-5 >> /tmp/t1.txt
        for line2 in `cat /tmp/t1.txt`
        do
                echo -n -e "$blue CONTAINER:$nocol "
                docker ps --format '{{.ID}}\t{{.Names}}' | grep $line2 | awk -F'\t' -v red="\033[1;95m" -v nocol="\033[0m" '{print red $2 nocol}'
        done
        echo
        rm /tmp/t1.txt
done
rm /tmp/t0.txt
