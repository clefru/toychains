#! /usr/bin/env nix-shell
#! nix-shell -i python2 -p "with python2Packages; [python pysha3 ed25519]"

import hashlib
import ed25519
import collections

Input = collections.namedtuple("Input", ["tx_id", "index"])
Output = collections.namedtuple("Output", ["pub_key", "amount"])


class InputReferenceError(Exception):
    pass


class BadSignatureError(Exception):
    pass


class Transaction(collections.namedtuple("Transaction", ["inputs", "outputs"])):
    
    def tx_id(self):
        return hashlib.sha256(str(self)).digest()

    def make_witness(self, keys):
        tx_id = self.tx_id()
        return [k.sign(tx_id) for k in keys]


class Chain(object):

    def __init__(self, genesis):
        # Do not verify the genesis transaction
        self.utxo = {}
        self.add_utxo(genesis)

    def add_utxo(self, tx):
        tx_id = tx.tx_id()
        for o, idx in zip(tx.outputs, range(0, len(tx.outputs))):
            self.utxo[(tx_id, idx)] = o

    def process_tx(self, tx, witnesses):
        i_amount = 0
        tx_id = tx.tx_id()
        new_utxo = dict(self.utxo)
        for i, w in zip(tx.inputs, witnesses):
            # Input reference unspent outputs in previous
            # transactions. They do so with a tx_id and index
            # reference.
            try:
                o = new_utxo[(i.tx_id, i.index)]
                del new_utxo[(i.tx_id, i.index)]
            except KeyError:
                raise InputReferenceError("Input %s not found in utxo set" % str(i))

            try:
                # The witness must sign this tx_id with the pubkey in
                # the output referenced.
                o.pub_key.verify(w, tx_id)
            except ed25519.BadSignatureError:
                raise BadSignatureError("Invalid signature on input %s" % str(i))

            i_amount += o.amount

        o_amount = sum([o.amount for o in tx.outputs])
        if i_amount < o_amount:
            raise ValueError("output amounts %d exceed input amounts %d", o_amount, i_amount)

        self.utxo = new_utxo
        self.add_utxo(tx)


def new_key():
    return ed25519.create_keypair()
