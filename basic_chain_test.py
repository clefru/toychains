#! /usr/bin/env nix-shell
#! nix-shell -i python2 -p "with python2Packages; [python pysha3 ed25519]"

from basic_chain import *
import unittest

class TestFoo(unittest.TestCase):
    def setUp(self):
        self.satoshi_priv, self.satoshi_pub = new_key()
        self.genesis_tx = Transaction([], [Output(pub_key=self.satoshi_pub, amount=1000)])
        self.c = Chain(self.genesis_tx)
        
    def test_input_index_error(self):
        # Test invalid tx_id
        # Test valid tx_id with invalid index
        pass
    
    def test_double_spend(self):
        # Check against double spends        
        clemens_priv, clemens_pub = new_key()
        s_to_c = TransactionBuilder([
            Input(tx_id=self.genesis_tx.tx_id(),
                  index=0,
                  signature=self.satoshi_priv)], [
            Output(pub_key=self.satoshi_pub,
                   amount=900),
            Output(pub_key=clemens_pub,
                   amount=100)])
        self.c.process_tx(s_to_c)

        # Spend the new satoshi output
        satoshi1 = TransactionBuilder([
            Input(tx_id=s_to_c.tx_id(),
                  index=0,
                  signature=self.satoshi_priv)], [
            Output(pub_key=self.satoshi_pub,
                   amount=900)])
        self.c.process_tx(satoshi1)

        # Double spend new output
        satoshi2 = TransactionBuilder([
            Input(tx_id=s_to_c.tx_id(),
                  index=0,
                  signature=self.satoshi_priv)], [
            Output(pub_key=self.satoshi_pub,
                   amount=900)])
        with self.assertRaises(ValueError):
            self.c.process_tx(satoshi2)
    
    def test_amounts(self):
        # Check against amount exceeds
        clemens_priv, clemens_pub = new_key()
        s_to_c = TransactionBuilder([
            Input(tx_id=self.genesis_tx.tx_id(),
                  index=0,
                  signature=self.satoshi_priv)], [
            Output(pub_key=self.satoshi_pub,
                   amount=900),
            Output(pub_key=clemens_pub,
                   amount=1000)])
        with self.assertRaises(ValueError):
          self.c.process_tx(s_to_c)

    def test_wrong_sigs(self):
        # Check against wrong signatures
        clemens_priv, clemens_pub = new_key()
        s_to_c = TransactionBuilder([
            Input(tx_id=self.genesis_tx.tx_id(),
                  index=0,
                  signature=clemens_priv)], [
            Output(pub_key=self.satoshi_pub,
                   amount=900),
            Output(pub_key=clemens_pub,
                   amount=100)])
        with self.assertRaises(ValueError):
            self.c.process_tx(s_to_c)

if __name__ == '__main__':
    unittest.main()
