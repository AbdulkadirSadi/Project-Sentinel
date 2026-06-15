#!/usr/bin/env python3
import sys

SRC = '/home/quietus/Project-Sentinel/agents/LinuxAgent/linux_agent.c'
src = open(SRC).read()
idx = src.find('    while (1) {\n        current_sock = socket')
print("idx =", idx)
print(repr(src[idx:idx+500]))
