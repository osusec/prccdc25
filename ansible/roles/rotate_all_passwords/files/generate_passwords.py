#!/usr/bin/env python3
# Yes, this *should* be an action plugin or module.
import secrets
import sys


def gen_passwords(pass_len: int = 16, num: int = 50):
    # C(67,16) = good luck!
    gen_set = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!#$%&"
    return [
        "".join([secrets.choice(gen_set) for _ in range(pass_len)]) for _ in range(num)
    ]


args = {}
if len(sys.argv) == 3:
    args["pass_len"] = int(sys.argv[1])
    args["num"] = int(sys.argv[2])
else:
    print("USAGE:\n    generate_passwords.py <password_length> <number_to_generate>")
    sys.exit(1)

print("\n".join(gen_passwords(**args)))
