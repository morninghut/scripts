#!/bin/bash
# check which docker is using GPU
nvidia-smi | grep python | awk '$4 {print $5}' | awk ' !x[$0]++' >> /tmp/t0.txt
for line in `cat /tmp/t0.txt`
do
        echo pid:
        echo "  $line"
        cat /proc/$line/cgroup | awk ' NR==1 ' | tr '/' ' ' | awk '$3 {print $3}' | cut -c 1-5 >> /tmp/t1.txt
        for line2 in `cat /tmp/t1.txt`
        do
                echo docker:
                docker ps | grep $line2 | awk '$11 {print $15}'
        done
        echo
        rm /tmp/t1.txt
        #echo test
        #echo $dockername
        #echo dockername:$dockername
        #shortname=echo $dockername | cut -c 1-5
        #echo $shortname
        #docker ps | grep 9253
        # | grep $dockername
        #echo $dockername | awk 'NR==1{print}'
done
rm /tmp/t0.txt
