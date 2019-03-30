#! /usr/bin/env nix-shell
#! nix-shell -i python2 -p "with python2Packages; [python]"

import hashlib
import collections
import os
import random

from toycrypto.ec import *
from toycrypto.primefields import *


p = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1
z = Z(p)
secp256k1 = EC(z, z.make(0), z.make(7))
# This random value for G is a random value. Trust me. Winkwink. Follow https://people.xiph.org/~greg/confidential_values.txt suggestion of taking the sha256 of the generator H
G = secp256k1.fromX(z.make(0x19BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81797))
H = secp256k1.fromX(z.make(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798))

# I could rename this open commitment
class OwnedOutput(collections.namedtuple("OwnedOutput", ["value", "bf"])):
    @classmethod
    def generate(cls, value):
      return OwnedOutput(value, Signature.gen_private_key())

    # Rename this function .commit()?
    def blind(self):
        res = secp256k1.plus(H.scalarMul(int(self.bf)), G.scalarMul(self.value))
#        print "%s * G + %s * H = %s" % (self.value, self.bf, res)
        return res


class InputReferenceError(Exception):
    pass


class BadSignatureError(Exception):
    pass


class OwnedTransaction(collections.namedtuple("OwnedTransaction", ["inputs", "outputs"])):

    def close(self, excess_r):
        """Closes the transaction with adding excess_r"""
        v = sum([o.value for o in self.inputs] + [-o.value for o in self.outputs])
        r = reduce(Signature.nF.plus, [o.bf for o in self.inputs] + [o.bf.plusInv() for o in self.outputs], excess_r)
        t = Transaction(inputs = [o.blind() for o in self.inputs],
                        outputs = [o.blind() for o in self.outputs],
                        excess = OwnedOutput(0, excess_r).blind(),
                        signature = Signature.sign(Signature.WITNESS_MAGIC, excess_r))
        return (t, v, r)


class Transaction(collections.namedtuple("Transaction", ["inputs", "outputs", "excess", "signature"])):

    @classmethod
    def merge(cls, t1, t2):
        return Transaction(inputs = t1.inputs + t2.inputs,
                           outputs = t1.outputs + t2.outputs,
                           excess = secp256k1.plus(t1.excess, t2.excess),
                           signature = Signature.merge(t1.signature, t2.signature))

    def sum(self):
        """Returns the transaction sum."""
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
        # v == 0, r == 0. If we would know 'r', we could check that with:
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
            raise ValueError("tx.sum not zero")

        if not tx.signature.verify(tx.excess, Signature.WITNESS_MAGIC):
            # tx.excess was not proven to be of the form v*G + r*H with
            # v == 0. It might have a negative 'v' and therefore
            # the tx might have created money out of nothing. Reject.
            raise BadSignatureError("Invalid signature on excess.")

        new_utxo.update(tx.outputs)
        self.utxo = new_utxo


class Actor():
    """Mimblewimble actor, and wallet owner."""

    def __init__(self, txs, c):
        # Set of owned outputs
        self.wallet = set(txs)
        self.chain = c

    def generate_output(self, v):
        """Generates outputs claiming 'v' amount of coins."""
        # FIXME add more change outputs for confusion
        new_output = [OwnedOutput.generate(v)]
        self.wallet.update(new_output)
        return new_output

    def coins_owned(self):
        """Return the amount of coins owned by this wallet at the current chain UTXO state."""
        return sum([t.value for t in self.wallet if (t.blind() in self.chain.utxo)])

    def select_inputs(self, n):
        """Selects inputs worth 'n', and returns change outputs."""
        owned_outputs = []
        candidates = set(self.wallet)
        while sum([i.value for i in owned_outputs]) < n and candidates:
            # FIXME add a few unrelated inputs for confusion
            c = random.choice(list(candidates))
            if c.blind() in self.chain.utxo:
                owned_outputs += [c]
            candidates.remove(c)

        change = sum([o.value for o in owned_outputs]) - n
        if change < 0:
            raise ValueError("Not enough coins")
        return (owned_outputs, self.generate_output(change))

    def send(self, n):
        """Creates a transaction sending 'n' coins."""
        owned_outputs, change_outputs = self.select_inputs(n)

        (t, v, r) = OwnedTransaction(inputs = owned_outputs,
                                     outputs = change_outputs).close(Signature.gen_private_key())
        assert v == n
        return (t, v, r)

    def receive(self, t):
        sending_tx, sending_v, sending_r = t

        # The sum of the sending_tx is:
        #   sending_v * G + sending_r * H
        #
        # First, check that this is indeed the case, so that we are not
        # cheated by the sending party to believe we receive more
        # coins than we actually do get.

        if not sending_tx.sum() == OwnedOutput(sending_v, sending_r).blind():
            raise ValueError("Incorrect opening information. Not receiving the stated amount of coins?")

        # Second, we need to create a transaction that balances out the sending_v by adding these amounts
        # to the transaction outputs:

        new_outputs = self.generate_output(sending_v)

        # And thirdly, we need to also balance out
        # sending_r. sending_r could be understood as the H
        # coefficient that is excessive, which when subtracted makes
        # the zero, as in
        #
        #   sum_v * G + sum_r * H - sending_r * H = 0
        #
        # To balance the transaction, we subtract sending_r from our excess.
        #
        # Note that:
        # * We cannot subtract sending_r * H from any input, as the blockchain
        #   will not have those points in the utxo set upon verification.
        #   FIXME introduce a test for this
        # * We cannot subtract sending_r * H from any given output, as this will
        #   break the attached rangeproofs. FIXME, is this true?! introduce a
        #   test for this
        # * We could subtract it from our output, but that's just shifting
        #   around values, and ultimately doesn't change anything.

        excess_r = reduce(Signature.nF.plus, [t.bf for t in new_outputs], sending_r.plusInv())

        (receiving_tx, receiving_v, receiving_r) = OwnedTransaction([], new_outputs).close(excess_r)

        # Check that transaction parts, when merged, equate to 0*G + 0*H.
        assert (receiving_v + sending_v) == 0
        assert Signature.nF.plus(receiving_r, sending_r).isPlusID()

        return Transaction.merge(sending_tx, receiving_tx)


class Signature(collections.namedtuple("Signature", ["s", "K"])):
    """Schnorr signatures over secp256k1."""
    Hfield = ECSubfield(secp256k1, H, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)
    nF = Z(Hfield.order)

    # Public reference scalar to be signed. This is usually the message
    # hash converted to a scalar. But as the message is public, its hash
    # is public as well, so we just define a public reference scalar right
    # away.
    WITNESS_MAGIC = 0xC0DED00D # Google that

    @classmethod
    def sign(cls, e, x):
        k = cls.gen_private_key()
        s = cls.nF.plus(k, cls.nF.mul(x, cls.nF.make(e)))
        return Signature(s, cls.Hfield.make(int(k)).point)

    @classmethod
    def merge(cls, s1, s2):
        return Signature(cls.nF.plus(s1.s, s2.s), secp256k1.plus(s1.K, s2.K))

    def verify(self, pubKey, e):
        S = Signature.Hfield.make(int(self.s)).point
        V = Signature.Hfield.ec.plus(self.K, pubKey.scalarMul(e))
        return S == V

    @classmethod
    def gen_private_key(cls):
        return cls.nF.make(random.randrange(1, Signature.Hfield.order))
#        return cls.nF.fromInt(random.randrange(1, 30))
