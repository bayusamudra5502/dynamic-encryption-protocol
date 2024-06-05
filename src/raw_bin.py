from lib.crypto.csprng import *
from lib.util import *
from random import random, SystemRandom
import os

RANDOM: CSPRNG = HenonMap(random(), random(), random())
FILE = "random_urandom.dat"
SIZE = 500_000_000

if __name__ == "__main__":
    with open(FILE, "wb") as f:
        for _ in range(SIZE):
            # RANDOM = RANDOM.next()
            # linear = to_linear(RANDOM.get_value(), size=8)
            linear = os.urandom(1)

            f.write(linear)

print("Done:", FILE)
