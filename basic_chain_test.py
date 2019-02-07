#! /usr/bin/env nix-shell
#! nix-shell -i python2 -p "with python2Packages; [python ed25519]"

from basic_chain import *
import unittest

class TestFoo(unittest.TestCase):
    def setUp(self):
        self.satoshi_priv, self.satoshi_pub = new_key()
        self.genesis_tx = Transaction([], [Output(pub_key=self.satoshi_pub, amount=1000)])
        self.c = Chain(self.genesis_tx)
        self.clemens_priv, self.clemens_pub = new_key()

    def test_input_txid_error(self):
        tx = Transaction([], [])
        s_to_c = Transaction(
            [Input(tx_id=tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=100)])
        with self.assertRaises(InputReferenceError):
            self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

    def test_input_index_error(self):
        s_to_c = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=1)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=100)])
        with self.assertRaises(InputReferenceError):
            self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

    def test_double_spend_tx(self):
        """Tests double spending an output with two txs."""
        s_to_c = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=100)])
        self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))
        with self.assertRaises(InputReferenceError):
            self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

    def test_double_spend_input(self):
        """Tests double spending an output within the same tx by making it an input twice."""
        tx = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=0),
             Input(tx_id=self.genesis_tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=2000)])
        with self.assertRaises(InputReferenceError):
            self.c.process_tx(tx, tx.make_witness([self.satoshi_priv, self.satoshi_priv]))

    def test_split_and_combine(self):
        # tx1: Satoshi sends 100 coins to clemens, and takes 900 into a change output.
        # tx2: Satoshi moves the 900 change output one more time.
        # tx3: Clemens & Satoshi recombine 100 + 900 into the genesis like 1000.
        s_to_c = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=100)])
        s_to_s = Transaction(
            [Input(tx_id=s_to_c.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900)])
        self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

        # Spend the new satoshi output
        self.c.process_tx(s_to_s, s_to_s.make_witness([self.satoshi_priv]))
        recombine = Transaction(
            [Input(tx_id=s_to_c.tx_id(), index=1),
             Input(tx_id=s_to_s.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=1000)])
        self.c.process_tx(recombine, recombine.make_witness([self.clemens_priv, self.satoshi_priv]))

    def test_amounts(self):
        # Check against amount exceeds
        s_to_c = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=1000)])
        with self.assertRaises(ValueError):
          self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

    def test_wrong_sigs(self):
        # Check against wrong signatures
        # Sign with clemens' key instead of satoshi's.
        s_to_c = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=100)])
        with self.assertRaises(BadSignatureError):
            self.c.process_tx(s_to_c, s_to_c.make_witness([self.clemens_priv]))

if __name__ == '__main__':
    unittest.main()
