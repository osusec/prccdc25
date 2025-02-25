#!/bin/bash

echo “kernel.yama.ptrace_scope = 1” >> /etc/sysctl.conf
sysctl -p /etc/sysctl.conf