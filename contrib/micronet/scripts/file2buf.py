#!/usr/bin/env python3

import os
import sys

MAX = 8

fpath = sys.argv[1]
name = sys.argv[2]

with open(fpath, "rb") as fh:
    sys.stdout.write("char %s[] = {" % (name,) )

    i = 0
    while True:
        if i > 0:
            sys.stdout.write(", ")

        if i % MAX == 0:
            sys.stdout.write("\n\t")

        c = fh.read(1)

        if not c:
            sys.stdout.write("\n")
            break

        sys.stdout.write("0x%.2x" % (ord(c), ))

        i = i + 1

    print("};")
    print("")
    print("unsigned int %s_sz = %s;" % (name, i))
    print("")

