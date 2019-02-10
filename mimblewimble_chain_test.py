#! /usr/bin/env nix-shell
#! nix-shell -i python2 -p "with python2Packages; [python]"

from mimblewimble_chain import *
import unittest


class GeneratorTests(unittest.TestCase):
    """Tests the used G, H values for being generator."""
    def test_commutitative_G_G(self):
        p1 = secp256k1.plus(G.scalarMul(5), G.scalarMul(7))
        p2 = secp256k1.plus(G.scalarMul(7), G.scalarMul(5))
        self.assertEqual(p1, p2)

    def test_commutitative_G_H(self):    
        p1 = secp256k1.plus(G.scalarMul(5), H.scalarMul(7))
        p2 = secp256k1.plus(H.scalarMul(7), G.scalarMul(5))
        self.assertEqual(p1, p2)

    def test_scalar_G(self):    
        p1 = secp256k1.plus(G.scalarMul(5), G.scalarMul(7))
        p2 = G.scalarMul(12)
        self.assertEqual(p1, p2)

    def test_scalar_H(self):    
        p1 = secp256k1.plus(H.scalarMul(5), H.scalarMul(7))
        p2 = H.scalarMul(12)
        self.assertEqual(p1, p2)

    def test_full_cross_G_H(self):    
        p11 = secp256k1.plus(G.scalarMul(5), H.scalarMul(7))
        p12 = secp256k1.plus(G.scalarMul(11), H.scalarMul(13))
        
        p1 = secp256k1.plus(p11, p12)
        p2 = secp256k1.plus(G.scalarMul(16), H.scalarMul(20))
        self.assertEqual(p1, p2)
    

class TestFoo(unittest.TestCase):
    def setUp(self):
        genesis_output = OwnedOutput.generate(1000)
        self.genesis_tx = Transaction([], [genesis_output.blind()], None, None)
        self.c = Chain(genesis_output.blind())
        self.satoshi = Actor([genesis_output], self.c)
        self.clemens = Actor([], self.c)
#        testy()

    def test_null(self):
        self.c.process_tx(self.clemens.receive(self.satoshi.send(100)))
        with self.assertRaises(ValueError):
            self.c.process_tx(self.satoshi.receive(self.clemens.send(150)))
        self.c.process_tx(self.clemens.receive(self.satoshi.send(150)))
        with self.assertRaises(ValueError):
            self.c.process_tx(self.clemens.receive(self.satoshi.send(1050)))
        self.c.process_tx(self.satoshi.receive(self.clemens.send(250)))
                          
    def xtest_input_txid_error(self):
        tx = Transaction([], [])
        s_to_c = Transaction(
            [Input(tx_id=tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=100)])
        with self.assertRaises(InputReferenceError):
            self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

    def xtest_input_index_error(self):
        s_to_c = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=1)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=100)])
        with self.assertRaises(InputReferenceError):
            self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

    def xtest_double_spend_tx(self):
        """Tests double spending an output with two txs."""
        s_to_c = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=100)])
        self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))
        with self.assertRaises(InputReferenceError):
            self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

    def xtest_double_spend_input(self):
        """Tests double spending an output within the same tx by making it an input twice."""
        tx = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=0),
             Input(tx_id=self.genesis_tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=2000)])
        with self.assertRaises(InputReferenceError):
            self.c.process_tx(tx, tx.make_witness([self.satoshi_priv, self.satoshi_priv]))

    def xtest_split_and_combine(self):
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

    def xtest_amounts(self):
        # Check against amount exceeds
        s_to_c = Transaction(
            [Input(tx_id=self.genesis_tx.tx_id(), index=0)],
            [Output(pub_key=self.satoshi_pub, amount=900),
             Output(pub_key=self.clemens_pub, amount=1000)])
        with self.assertRaises(ValueError):
          self.c.process_tx(s_to_c, s_to_c.make_witness([self.satoshi_priv]))

    def xtest_wrong_sigs(self):
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
