#!/usr/bin/env python

from Crypto.Random import get_random_bytes

rb = get_random_bytes(16)

ps_bytes = list(rb)
py_bytes = []
for i in ps_bytes:
    py_bytes.append(str(hex(i)).replace("0x", ""))
print("PS: " + str(ps_bytes))
print("Py: " + str(py_bytes))
