#! /usr/bin/env nix-shell
#! nix-shell -i python2 -p "with python2Packages; [python]"

import hashlib
import collections
import os
import random
from tmath import *


p = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1
z = Z(p)
secp256k1 = EC(z, z.fromInt(0), z.fromInt(7))
# This random value for G is a random value. Trust me. Winkwink.
G = secp256k1.fromX(z.fromInt(0x19BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81797))
H = secp256k1.fromX(z.fromInt(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798))

class OwnedOutput(collections.namedtuple("OwnedOutput", ["value", "bf"])):
    @classmethod
    def generate(cls, value):
      return OwnedOutput(value, Signature.gen_private_key())

    def blind(self):
        res = secp256k1.plus(H.scalarMul(self.bf.toInt()), G.scalarMul(self.value))
#        print "%s * G + %s * H = %s" % (self.value, self.bf, res)
        return res


class InputReferenceError(Exception):
    pass


class BadSignatureError(Exception):
    pass


class OwnedTransaction(collections.namedtuple("OwnedTransaction", ["inputs", "outputs"])):

    def close2(self, excess_r):
        #v = sum([o.value for o in self.inputs] + [-o.value for o in self.outputs])

        #r = reduce(Signature.nF.plus, [o.bf for o in self.inputs] + [o.bf.plusInv() for o in self.outputs], excess.bf)

        t = Transaction(inputs = [o.blind() for o in self.inputs],
                        outputs = [o.blind() for o in self.outputs],
                        excess = H.scalarMul(excess_r.toInt()),
                        signature = Signature.sign(Signature.WITNESS_MAGIC, excess_r))
        return t
        return (t, v, r)
    def close(self):
        excess = OwnedOutput.generate(0)

        v = sum([o.value for o in self.inputs] + [-o.value for o in self.outputs])

        r = reduce(Signature.nF.plus, [o.bf for o in self.inputs] + [o.bf.plusInv() for o in self.outputs], excess.bf)

        t = Transaction(inputs = [o.blind() for o in self.inputs],
                        outputs = [o.blind() for o in self.outputs],
                        excess = excess.blind(),
                        signature = Signature.sign(Signature.WITNESS_MAGIC, r))
        return (t, v, r)


class Transaction(collections.namedtuple("Transaction", ["inputs", "outputs", "excess", "signature"])):

    @classmethod
    def merge(cls, t1, t2):
        return Transaction(inputs = t1.inputs + t2.inputs,
                           outputs = t1.outputs + t2.outputs,
                           excess = secp256k1.plus(t1.excess, t2.excess),
                           signature = Signature.merge(t1.signature, t2.signature))

    def sum(self):
        return reduce(secp256k1.plus, self.inputs + [o.plusInv() for o in self.outputs], self.excess)


class Chain(object):

    def __init__(self, genesis_output):
        # Do not verify the blinded genesis output point
        self.utxo = set([genesis_output])

    def process_tx(self, tx):
        new_utxo = set(self.utxo)
        for p in tx.inputs:
            if p not in new_utxo:
                raise InputReferenceError("Input %s not found in utxo set: %s" % (p, new_utxo))
            new_utxo.remove(p)

        # The transaction sum should have the form: v * G + r * H with
        # v == 0. If we would know 'r', we could check that with:
        #
        #   tx.sum() == secp256k1.plus(G.scalarMul(0), H.scalarMul(r)).
        #
        # But we do not know 'r'. Actually we do not really care which
        # value 'r' has, as long as the coefficient for G is zero as
        # this proves that the transaction is balanced and does not
        # create money. The main trick of Mimblewimble is to
        # reinterpret tx.sum() as public key under a EC signature
        # scheme, such as Schnorr signatures. Somebody that knows 'r'
        # can prove to us that the G-coefficient is zero, by using the
        # whole tx.sum() as public key and producing a signature using
        # 'r' which is the corresponding private key.
        #
        # It doesn't matter what is signed, only that the signature is
        # valid. We use a constant WITNESS_MAGIC as signature message.

        if not tx.sum().isPlusID():
            raise ValueError("inputs and outputs not balanced")

        if not tx.signature.verify(tx.excess, Signature.WITNESS_MAGIC):
            # tx.sum() was not proven to be of the form v*G + r*H with
            # v == 0. It might have a positive 'v' and therefore
            # created money out of nothing. We reject it.
            raise BadSignatureError("Invalid signature on tx.sum()")

        new_utxo.update(tx.outputs)
        self.utxo = new_utxo


class Actor():
    """Mimblewimble actor, and wallet owner."""

    def __init__(self, txs, c):
        # Set of owned outputs
        self.wallet = set(txs)
        self.chain = c


    def coins_owned(self):
        return sum([t.value for t in self.wallet if (t.blind() in self.chain.utxo)])
        x = 0
        for t in self.wallet:
            if t.blind() in self.chain.utxo:
                x += t.value
        return x

    def send(self, n):
        owned_outputs = []
        candidates = set(self.wallet)
        while sum([i.value for i in owned_outputs]) < n and candidates:
            c = random.choice(list(candidates))
            if c.blind() in self.chain.utxo:
                owned_outputs += [c]
            candidates.remove(c)
        # FIXME add a few unrelated inputs for conffusion

        change = sum([o.value for o in owned_outputs]) - n
        if change < 0:
            raise ValueError("Not enough coins")

        # FIXME add more change outputs for confusion
        new_outputs = [self.generate_output(change)]

        # We do not remove the used outputs as the transaction might
        # not hit the chain for some other reason.

#        excess = OwnedOutput.generate(0)

        v = sum([o.value for o in owned_outputs] + [-o.value for o in new_outputs])

        r = reduce(Signature.nF.plus, [o.bf.plusInv() for o in owned_outputs] + [o.bf for o in new_outputs])
 #       excess_value = r
        excess_value = Signature.gen_private_key()


#        t = Transaction(inputs = [o.blind() for o in owned_outputs],
#                        outputs = [o.blind() for o in new_outputs],
#                        excess = H.scalarMul(excess_value.toInt()),
#                        signature = Signature.sign(Signature.WITNESS_MAGIC, excess_value))
        t = OwnedTransaction(inputs = owned_outputs,
                             outputs = new_outputs).close2(excess_value)
#        (t, v, r) = OwnedTransaction(inputs = owned_outputs, outputs = new_outputs).close()
#        assert t.sum() == OwnedOutput(100, Signature.nF.fromInt(0)).blind()
        assert v == n
# FIXME is this a security risk if r=0?
        return (t, v, Signature.nF.plus(r.plusInv(), excess_value))


    def generate_output(self, v):
        new_output = OwnedOutput.generate(v)
        self.wallet.update([new_output])
        return new_output

    def receive(self, t):
        sending_tx, v, r = t
        # Verify with the opening information that we receive the
        # amounts of coins that we think we get.
        if not sending_tx.sum() == OwnedOutput(v, r).blind():
            raise ValueError("Incorrect opening information. Not receiving the stated amount of coins?")

        # The given transaction is excessive in H by r. We create our excess value to offset that.
        # The given transaction is excessive in G by v. We create an output to claim that money.

        new_output = self.generate_output(v)
        excess_r = Signature.nF.plus(new_output.bf, r.plusInv())

        receiving_tx = Transaction(inputs = [],
                                   outputs = [new_output.blind()],                                 # v*G + bf*H
                                   excess = H.scalarMul(excess_r.toInt()),                         # 0*G + bf*H - r*H .. so that its summed
                                                                                                   # together only -v*G remains.
                                   signature = Signature.sign(Signature.WITNESS_MAGIC, excess_r))

        return Transaction.merge(sending_tx, receiving_tx)

    def receive2(self, t):
        sending_tx, v, r = t
        print v, r
        if not sending_tx.sum() == OwnedOutput(v, r).blind():
            raise ValueError("Incorrect opening information. Not receiving the stated amount of coins?")

        # FIXME: Also verify signature.. but really the signature
        # isn't necessary at all as it can be recreated from r.

        # FIXME generate more than one output for privacy
        receiving_tx = OwnedTransaction(inputs = [], outputs = [OwnedOutput.generate(v)])

        # Add the newly created outputs to wallet
        self.wallet.update(receiving_tx.outputs)

        # Creates a balanced transaction that creates no-money.
        return Transaction.merge(sending_tx, receiving_tx.close()[0])


class Signature(collections.namedtuple("Signature", ["s", "K"])):
    """Schnorr signatures."""
    Hfield = ECSubfield(secp256k1, H, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
    nF = Z(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

    # Public reference scalar to be signed. This is usually the message
    # hash converted to a scalar. But as the message is public, its hash
    # is public as well, so we just define a public reference scalar right
    # away.
    WITNESS_MAGIC = 0xC0DED00D # Google that

    @classmethod
    def sign(cls, e, x):
        k = cls.gen_private_key()
        s = cls.nF.plus(k, cls.nF.mul(x, cls.nF.fromInt(e)))
        return Signature(s, cls.Hfield.fromInt(k.toInt()).point)

    @classmethod
    def merge(cls, s1, s2):
        return Signature(cls.nF.plus(s1.s, s2.s), secp256k1.plus(s1.K, s2.K))

    def verify(self, pubKey, e):
        S = Signature.Hfield.fromInt(self.s.toInt()).point
        V = Signature.Hfield.ec.plus(self.K, pubKey.scalarMul(e))
        return S == V

    @classmethod
    def gen_private_key(cls):
#        return cls.nF.fromInt(random.randrange(1, Signature.Hfield.order))
        return cls.nF.fromInt(random.randrange(1, 30))

#seed = random.randrange(0,100000)
seed = 70
print seed
random.seed(seed)
