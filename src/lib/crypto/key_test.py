from cryptography.hazmat.primitives.asymmetric import ec
from lib.crypto.key import *


def test_generate_shared_key():
    alice = ec.generate_private_key(ec.SECP256R1())
    bob = ec.generate_private_key(ec.SECP256R1())

    alice_public = alice.public_key()
    bob_public = bob.public_key()

    # Alice
    alice_key = generate_shared_secret(bob_public, alice)

    # Bob
    bob_key = generate_shared_secret(alice_public, bob)

    assert alice_key == bob_key


def test_master_secret():
    alice = ec.generate_private_key(ec.SECP256R1())
    bob = ec.generate_private_key(ec.SECP256R1())

    alice_public = alice.public_key()
    bob_public = bob.public_key()

    # Alice
    alice_key = generate_shared_secret(bob_public, alice)

    # Bob
    bob_key = generate_shared_secret(alice_public, bob)

    assert alice_key == bob_key

    alice_master = generate_master_secret(alice_key, b"client", b"server")
    bob_master = generate_master_secret(bob_key, b"client", b"server")

    assert alice_master == bob_master


def test_chaos_parameter():
    alice = ec.generate_private_key(ec.SECP256R1())
    bob = ec.generate_private_key(ec.SECP256R1())

    alice_public = alice.public_key()
    bob_public = bob.public_key()

    # Alice
    alice_key = generate_shared_secret(bob_public, alice)

    # Bob
    bob_key = generate_shared_secret(alice_public, bob)

    assert alice_key == bob_key

    alice_master = generate_master_secret(alice_key, b"client", b"server")
    bob_master = generate_master_secret(bob_key, b"client", b"server")

    assert alice_master == bob_master

    alice_aes1, alice_aes2, alice_hmac1, alice_hmac2 = generate_chaos_parameter(
        alice_master, b"client", b"server")
    bob_aes1, bob_aes2, bob_hmac1, bob_hmac2 = generate_chaos_parameter(
        bob_master, b"client", b"server")

    assert alice_aes1 == bob_aes1
    assert alice_aes2 == bob_aes2
    assert alice_hmac1 == bob_hmac1
    assert alice_hmac2 == bob_hmac2

    enc = alice_aes1.encrypt(b"Miuu")
    dec = bob_aes1.decrypt(enc)

    assert dec == b"Miuu"

    mac = alice_hmac1.generate(b"Hello")
    assert bob_hmac1.verify(b"Hello", mac)

    enc = bob_aes1.encrypt(b"Miuu")
    dec = alice_aes1.decrypt(enc)

    assert dec == b"Miuu"

    mac = bob_hmac1.generate(b"Hello")
    assert alice_hmac1.verify(b"Hello", mac)
