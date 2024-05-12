from lib.crypto.csprng import *
from random import random


def test_chaos():
    x = SineHenonMap(random(), random(), random())

    assert x == x

    for _ in range(10):
        tmp = x.next()
        assert x != tmp

        x = tmp
