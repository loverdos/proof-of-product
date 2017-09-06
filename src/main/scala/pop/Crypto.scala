package pop

import java.math.BigInteger
import java.security.SecureRandom

import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.{DJKeyGenParameterSpec, ScDamgardJurikEnc}
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.{DamgardJurikPrivateKey, DamgardJurikPublicKey}
import edu.biu.scapi.midLayer.ciphertext.BigIntegerCiphertext
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText
import org.bouncycastle.util.BigIntegers

final case class DJKeyPair(
  publicKey: DamgardJurikPublicKey,
  privateKey: DamgardJurikPrivateKey
)

// crypto-helpers
object Crypto {
  // The type of numbers we use
  final type Number = BigInteger
  // The type of encrypted numbers we use
  final type CNumber = BigIntegerCiphertext

  final type EncryptF = (Number) ⇒ CNumber
  final type DecryptF = (CNumber) ⇒ Number

  final val ZERO = BigInteger.ZERO
  final val ONE = BigInteger.ONE

  def newDJKeyPair(encScheme: ScDamgardJurikEnc): DJKeyPair = {
    val keyPair = encScheme.generateKey(new DJKeyGenParameterSpec)
    val publicKey = keyPair.getPublic.asInstanceOf[DamgardJurikPublicKey]
    val privateKey = keyPair.getPrivate.asInstanceOf[DamgardJurikPrivateKey]

    DJKeyPair(publicKey, privateKey)
  }

  def newDJKeyPair(random: SecureRandom): DJKeyPair = {
    val encScheme = new ScDamgardJurikEnc(random)
    newDJKeyPair(encScheme)
  }

  def newDJScheme(random: SecureRandom): (ScDamgardJurikEnc, DJKeyPair) = {
    val encScheme = new ScDamgardJurikEnc(random)
    val djKeyPair = newDJKeyPair(encScheme)
    encScheme.setKey(djKeyPair.publicKey, djKeyPair.privateKey)

    (encScheme, djKeyPair)
  }

  def djEncrypt(encScheme: ScDamgardJurikEnc, n: BigInteger): BigIntegerCiphertext = {
    val plaintext = new BigIntegerPlainText(n)
    encScheme.encrypt(plaintext).asInstanceOf[BigIntegerCiphertext]
  }

  def djDecrypt(encScheme: ScDamgardJurikEnc, ciphertext: BigIntegerCiphertext): BigInteger = {
    val plaintext = encScheme.decrypt(ciphertext).asInstanceOf[BigIntegerPlainText]
    plaintext.getX
  }

  def createRandomInRange(a: BigInt, b: BigInt, random: SecureRandom): BigInt =
    BigIntegers.createRandomInRange(a.bigInteger, b.bigInteger, random)

  def createRandomInRange(a: Int, b: BigInt, random: SecureRandom): BigInt = {
    val big_a = BigInt(a.toString)
    createRandomInRange(big_a, b, random)
  }

  /**
   * Computes the randomness `r` from a ciphertext `c`, `p` coming from
   * [[edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDamgardJurikPrivateKey#getP]]
   * and `q` coming from
   * [[edu.biu.scapi.midLayer.asymmetricCrypto.keys.ScDamgardJurikPrivateKey#getQ]].
   */
  def computeR(c: CNumber, p: BigInt, q: BigInt): BigInt = {
    val n = p * q
    val `(p-1)(q-1)` = (p - 1) * (q - 1)
    val m = n modInverse `(p-1)(q-1)`

    val cc = BigInt(c.getCipher)
    cc.modPow(m, n)
  }

  // Not so Crypto-related but OK let's put it here.
  /**
   * Checks that a series of numbers are all relatively prime to `n`.
   */
  def areRelativelyPrimeToN(n: BigInteger, others: BigInteger*): Boolean = {
    def check(i: Int): Boolean =
      if(i >= others.length) true // exhausted the sequence and were unable to falsify, so we are OK
      else if( others(i).gcd(n) != ONE ) false
      else check(i + 1)

    require(others.nonEmpty, "others.nonEmpty")

    check(0)
  }
}
