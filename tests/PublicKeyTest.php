<?php

use NZTim\Crypto\PublicKey\CryptoBoxSeal;
use NZTim\Crypto\PublicKey\KeyPair;
use PHPUnit\Framework\TestCase;

class PublicKeyTest extends TestCase
{
    /** @test */
    public function generate()
    {
        $kp = KeyPair::generate();
        $this->assertTrue($kp instanceof KeyPair);
    }

    /** @test */
    public function from_seed()
    {
        $kp1 = KeyPair::generate();
        $seed = $kp1->toString();
        $kp2 = KeyPair::fromString($seed);
        $this->assertEquals($kp1->toString(), $kp2->toString());
    }

    /** @test */
    public function public_keys_and_seeds()
    {
        $kp1 = KeyPair::generate();
        $kp2 = KeyPair::fromString($kp1->toString());
        $pk1 = $kp1->publicKey();
        $pk2 = $kp2->publicKey();
        $this->assertEquals($pk1->toString(), $pk2->toString());
        $this->assertEquals($pk1->binaryKey(), $pk2->binaryKey());
    }

    /** @test */
    public function encrypt_decrypt()
    {
        $kp = KeyPair::generate();
        $pk = $kp->publicKey();
        $plaintext = 'Hello World!';
        $cbs = new CryptoBoxSeal();
        $ciphertext = $cbs->encrypt($plaintext, $pk);
        $this->assertEquals($plaintext, $cbs->decrypt($ciphertext, $kp));
    }
}
