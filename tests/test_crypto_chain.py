import pytest
from cryptography.exceptions import InvalidTag

from pop_sim import crypto
from pop_sim.blockchain import Blockchain, Transaction


def test_sign_verify_roundtrip():
    k = crypto.generate_keypair()
    sig = crypto.sign(k.sk, b"hello")
    assert crypto.verify(k.pk, b"hello", sig)
    assert not crypto.verify(k.pk, b"hellO", sig)
    other = crypto.generate_keypair()
    assert not crypto.verify(other.pk, b"hello", sig)


def test_encrypt_only_recipient_can_decrypt():
    a, b = crypto.generate_keypair(), crypto.generate_keypair()
    blob = crypto.encrypt(a.pk, b"secret")
    assert crypto.decrypt(a.sk, blob) == b"secret"
    with pytest.raises(InvalidTag):
        crypto.decrypt(b.sk, blob)


def test_transaction_is_signed_and_encrypted_for_receiver():
    s, r = crypto.generate_keypair(), crypto.generate_keypair()
    tx = Transaction.create("shuffle", s, r.pk, {"pids": ["a", "b"]})
    assert tx.verify_signature()
    assert tx.open(r) == {"pids": ["a", "b"]}
    last = int(tx.ciphertext[-2:], 16) ^ 0x01          # flip one bit: always a real change
    tx.ciphertext = tx.ciphertext[:-2] + f"{last:02x}"
    assert not tx.verify_signature()


def test_chain_links_and_detects_tampering():
    s, r = crypto.generate_keypair(), crypto.generate_keypair()
    bc = Blockchain()
    for i in range(3):
        tx = Transaction.create("used", s, r.pk, {"i": i})
        bc.add_block(bc.new_block([tx], miner="PM-1", consensus="pop"))
    assert len(bc) == 4 and bc.is_valid()
    bc.chain[2].transactions[0].timestamp += 1
    assert not bc.is_valid()


def test_chain_rejects_unlinked_block():
    bc = Blockchain()
    blk = bc.new_block([], miner="x", consensus="pop")
    blk.previous_hash = "0" * 64
    with pytest.raises(ValueError):
        bc.add_block(blk)
