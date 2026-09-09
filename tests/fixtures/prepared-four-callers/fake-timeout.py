#!/usr/bin/env python3
import os
import sys
from fixture_common import record, refuse

record("timeout")
arguments = sys.argv[1:]
index = 0
while index < len(arguments) and arguments[index].startswith("-"):
    index += 1
if index >= len(arguments):
    refuse("timeout duration missing")
index += 1
if index >= len(arguments):
    refuse("timeout command missing")
os.execv(arguments[index], arguments[index:])
