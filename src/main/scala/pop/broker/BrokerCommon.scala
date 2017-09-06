package pop
package broker

import java.security.SecureRandom

import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScDamgardJurikEnc
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey

abstract class BrokerCommon private[broker](
  protocolParams: ProtocolParams,
  privateKey: DamgardJurikPrivateKey
) {
  // NOTE Do we need a more accurate computation (i.e. take into account Int boundaries)?
  require(3 * protocolParams.soundness < protocolParams.modulusBitLength, "soundness parameter is out of bounds" /*TODO More details?*/)

  protected val random = new SecureRandom()
  protected val djEncScheme = {
    val encScheme = new ScDamgardJurikEnc(protocolParams.random)
    encScheme.setKey(protocolParams.publicKey, privateKey)
    encScheme
  }

  protected val djEncryptF: Crypto.EncryptF = Crypto.djEncrypt(djEncScheme, _)
  protected val djDecryptF: Crypto.DecryptF = Crypto.djDecrypt(djEncScheme, _)
}
