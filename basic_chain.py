#! /usr/bin/env nix-shell
#! nix-shell -i python2 -p "with python2Packages; [python pysha3 ed25519]"

import hashlib
import ed25519

class Input(object):
    def __init__(self, tx_id, index, signature):
        self.tx_id = tx_id
        self.index = index
        self.signature = signature
        
    def __repr__(self):
        # The signature is not part of the representation
        return "I(%s, %s)" % (self.tx_id, self.index)

class Output(object):
    def __init__(self, pub_key, amount):
        self.pub_key = pub_key
        self.amount = amount
        self.spent = False
        
    def __repr__(self):
        # The spent attribute is not part of the representation
        return "O(%s, %s)" % (self.pub_key.to_ascii(encoding="hex"), self.amount)

class Transaction(object):
    def  __init__(self, inputs, outputs):
        self.inputs = inputs
        self.outputs = outputs

    def __repr__(self):
        return "T(%s, %s)" % (self.inputs, self.outputs)
    
    def tx_id(self):
        return hashlib.sha256(str(self)).digest()

class TransactionBuilder(Transaction):
    def __init__(self, inputs, outputs):
        # bind all signatures to None in input.
        # get tx_id
        super(TransactionBuilder, self).__init__(inputs, outputs)
        tx_id = self.tx_id()

        for i in self.inputs:
            i.signature = i.signature.sign(tx_id)

class Chain(object):
    def __init__(self, genesis):
        # Do not verify the genesis transaction
        self.txs = { genesis.tx_id(): genesis }
        self.utxo = {}
        self.add_utxo(genesis)

    def add_utxo(self, tx):
        i = 0
        for o in tx.outputs:
            self.utxo[(tx.tx_id(), i)] = o
            i += 1 
        
    def process_tx(self, tx):
        i_amount = 0
        tx_id = tx.tx_id()
        effects = []
        for i in tx.inputs:
#            os = self.txs[i.tx_id].outputs
#            if not i.index < len(os):
#                raise ValueError("Input has invalid reference %s" % str(i))
#            o = os[i.index]
            try:
                o = self.utxo[(i.tx_id, i.index)]
            except KeyError:
                raise ValueError("Input %s not found in utxo set" % str(i))
            
            try:
                o.pub_key.verify(i.signature, tx_id)
            except ed25519.BadSignatureError:
                raise ValueError("Invalid signature on input %s" % str(i))
#            if o.spent:
#                raise ValueError("Input is already spent %s" % str(i))
            def remove_utxo():
                del self.utxo[(i.tx_id, i.index)]
            effects += [remove_utxo]
            i_amount += o.amount

        o_amount = sum([o.amount for o in tx.outputs])
        if i_amount < o_amount:
            raise ValueError("output amounts %d exceed input amounts %d", o_amount, i_amount)

        # All checks passed. Modify our state
        for i in tx.inputs:
            o = self.txs[i.tx_id].outputs[i.index]
#            o.spent = True
        [e() for e in effects]
        self.txs[tx_id] = tx
        self.add_utxo(tx)

def new_key():
    return ed25519.create_keypair()
