#!/bin/bash
echo "192.168.10.1:55555" > /sys/kernel/debug/lframe/lframe_ctl 
echo "dport=80" > /sys/kernel/debug/lframe/tcpprobe_ctl 

