#! /usr/bin/env nix-shell
#! nix-shell -i python2 -p "with python2Packages; [python]"

import hashlib
import collections
import os
import random
from tmath import *

#Input = collections.namedtuple("Input", ["tx_id", "index"])
#Input = collections.namedtuple("Input", ["point"])
#BlindOutput = collections.namedtuple("BlindOutput", ["point"])


p = 2 ** 256 - 2 ** 32 - 2 ** 9 - 2 ** 8 - 2 ** 7 - 2 ** 6 - 2 ** 4 - 1
z = Z(p)
secp256k1 = EC(z, z.fromInt(0), z.fromInt(7))
# This random value for G is a random value. Trust me. Winkwink.
G = secp256k1.fromX(z.fromInt(0x19BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81797))
H = secp256k1.fromX(z.fromInt(0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798))
Hfield = ECSubfield(secp256k1, H, 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)      

class OwnedOutput(collections.namedtuple("OwnedOutput", ["value", "bf"])):
    def blind(self):
        res = secp256k1.plus(H.scalarMul(self.bf), G.scalarMul(self.value))
        print "%s * G + %s * H = %s" % (self.value, self.bf, res)
        return res


class InputReferenceError(Exception):
    pass


class BadSignatureError(Exception):
    pass



class OwnedTransaction(collections.namedtuple("Transaction", ["inputs", "outputs"])):
    def sign():
        pass

class Transaction(collections.namedtuple("Transaction", ["inputs", "outputs", "kernel", "signature"])):
    
    def tx_id(self):
        return hashlib.sha256(str(self)).digest()

    def sum(self):
        s = self.kernel
#        print "x", s
        for p in self.inputs:
#            print p
            s = secp256k1.plus(s, p)
        for p in self.outputs:
#            print p
            s = secp256k1.plus(s, p.plusInv())
        return s


class Chain(object):

    def __init__(self, genesis):
        # Do not verify the genesis transaction
        self.utxo = set()
        self.add_utxo(genesis)

    def add_utxo(self, tx):
        self.utxo.update([o for o in tx.outputs])


    def process_tx(self, tx):
        i_amount = 0
        new_utxo = set(self.utxo)
        ec = secp256k1.plusID()
        for p in tx.inputs:
            if p not in list(self.utxo):
                raise InputReferenceError("Input %s not found in utxo set: %s" % (p, self.utxo))
            self.utxo.remove(p)
            ec = secp256k1.plus(ec, p)

        for p in tx.outputs:
            ec = secp256k1.plus(ec, p.plusInv())
        ec = secp256k1.plus(ec, tx.kernel)

        # ec should be r * G + 0 * H. If this is indeed the case, then
        # r*G is a public key under Schnorr signatures or ecdsa
        # signatures. The transaction builders should have conspired
        # to get 'r' and should have signed the tx_id with r.
        if not schnorr2_verify(ec, "HELLO", tx.signature[0], tx.signature[1]):
            # not proven to be a zero-value commit.
            raise BadSignatureError("Invalid signature on excess")
        
        self.utxo = new_utxo
        self.add_utxo(tx)



#OwnedUTXO = namedtuple("OwnedUTXO", ["tx_id", "index", "value", "blinding_factor"])

def generate_output(value):
    return OwnedOutput(value, rscal())


def combine_blind_outputs(o1, o2):
    return BlindOutput(o1.point.add(o2.point))


class Actor():
    def __init__(self, txs):
        self.wallet = set(txs)
        
    def prove_ownership(tx_id, index, msg):
        bo = chain.utxo[(tx_id, index)]
        owned = self.wallet[bo]

        r1 = rscal()
        bo_r1, owned_r1 = generate_output(r1)
        # owned_r1.v *G + owned.v * G  + owned.bf * H + owned_r1.bf * H =
        # (owned_r1 + owned.v) * G + (owned.bf + owned_r1.bf) * H 
        x = combine_blind_output(bo_r1, bo)
        owned_r1.bf + owned.bf 

    def send(self, n):
        owned_outputs = []
        candidates = set(self.wallet)
        while sum([i.value for i in owned_outputs]) < n and candidates:
            c = random.choice(list(candidates))
            owned_outputs += [c]
            candidates.remove(c)
        # FIXME add a few unrelated inputs for confusion
        
        diff = sum([o.value for o in owned_outputs]) - n
        if diff < 0:
            raise ValueError("Not enough coins")

        # FIXME add more change outputs for confusion
        new_outputs = [generate_output(diff)]

        excess = generate_output(0)
        
        # The opening information on the sum is
        # the amount of coins sent and the sum of the blinding factors.
        v = sum([o.value for o in owned_outputs]) - sum([o.value for o in new_outputs])
        assert v == n
#        print [o.bf for o in owned_outputs], [o.bf for o in new_outputs], excess.bf
        r = sum([o.bf for o in owned_outputs]) - sum([o.bf for o in new_outputs]) + excess.bf
        
        t = Transaction(inputs = [o.blind() for o in owned_outputs],
                        outputs = [o.blind() for o in new_outputs],
                        kernel = excess.blind(),
                        #signature = None
                        signature = schnorr2_sign("HELLO", r)
        #                signature = excess.sign("HELLO")
        )
        return (t, v, r)
    
    def receive(self, t, v, r):
        # FIXME what do I need r for?
        # Verify
        a = t.sum()
#        b = secp256k1.plus(G.scalarMul(v), H.scalarMul(r))

        if not a == OwnedOutput(v, r).blind():
            raise ValueError("incorrect opening information.")
        new_outputs = [generate_output(v)]
        excess = generate_output(0)
        r = sum([]) - sum([o.bf for o in new_outputs]) + excess.bf
        mine = Transaction(inputs = [],
                           outputs = [o.blind() for o in new_outputs],
                           kernel = excess.blind(),
                           signature = schnorr2_sign("HELLO", r)
        #                   signature = excess.sign("HELLO")
        )
        self.wallet.update(new_outputs)
        m = mergeTransactions(t, mine)
#        if not m.sum() == OwnedOutput(0, 16).blind():
#            print "doesn't"
#        else:
#            print "XXXX"
#        fake = Transaction(inputs = m.inputs,
#                           outputs = m.outputs,
#                           kernel = m.kernel,
#                           signature = schnorr2_sign("HELLO", 16))
        return m
        
           
    def receive2(self, t, v, r):
        # Verify with the opening information that we receive the
        # amounts of coins that we think we get.
        if t.sum() != secp256k1.plus(G.scalarMul(v), H.scalarMul(r)):
            raise ValueError("incorrect opening information.")
        new_outputs = [generate_output(v)]
        e = rscal()
        new_e = H.scalamult(e)
        sign = e.sign("HELLO")
        modified = Transaction(inputs = t.inputs,
                               outputs = t.outputs + new_outputs,
                               kernel = t.kernel.subtract(new_outputs[0].point()),
                               signature = signature_merge(t.signature, sign))
        return modified

def mergeTransactions(t1, t2):
    return Transaction(inputs = t1.inputs + t2.inputs,
                       outputs = t1.outputs + t2.outputs,
                       kernel = secp256k1.plus(t1.kernel, t2.kernel),
                       signature = schnorr2_merge(t1.signature, t2.signature))



def hsh(msg):
    d = hashlib.sha256(msg).digest()
    return int(binascii.hexlify(d), 16)

def schnorr2_sign(msg, x):
  e = hsh(msg)
  
  nF = Z(Hfield.order)
  k = random.randrange(Hfield.order)
  s = nF.plus(nF.fromInt(k), nF.mul(nF.fromInt(x), nF.fromInt(e)))
  
  return (s.toInt(), Hfield.fromInt(k).point)

def schnorr2_merge(sig1, sig2):
    (s1, r1) = sig1
    (s2, r2) = sig2
    return (s1 + s2, secp256k1.plus(r1, r2))

def schnorr2_verify(pubKey, msg, s, K):
    e = hsh(msg)    
    S = Hfield.fromInt(s).point
    V = Hfield.ec.plus(K, pubKey.scalarMul(e))
    return S == V

#FIXME remove this
random.seed(14)
def rscal():
    # FIXME expand size
    return random.randrange(1, 20)
#    return random_scalar(os.urandom)
