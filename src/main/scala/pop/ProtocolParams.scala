package pop

import java.math.BigInteger
import java.security.SecureRandom

import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPublicKey

/**
 *
 * @param length    The length parameter, usually represented as `s`
 * @param soundness The soundness parameter, usually represented as `t`
 * @param random    The secure random number generator
 * @param publicKey The public key for the encrypted communication between the broker and the users.
 *                  Note that the broker owns the private key.
 */
final case class ProtocolParams(
  length: Int,
  soundness: Int,
  random: SecureRandom,
  publicKey: DamgardJurikPublicKey
) {

  val modulus: BigInteger = publicKey.getModulus
  val modulusBitLength: Int = modulus.bitLength()

  val n: BigInt = BigInt(modulus)
  val N: BigInt = n.pow(length)
}
