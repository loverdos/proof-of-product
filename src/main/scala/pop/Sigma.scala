package pop

object Sigma {
  import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.damgardJurikProduct._
  import edu.biu.scapi.interactiveMidProtocols.sigmaProtocol.utility._

  final type Msg = SigmaProtocolMsg

  final type CommonInput = SigmaDJProductCommonInput
  final type ProverInput = SigmaDJProductProverInput
  final type ProverComputation = SigmaDJProductProverComputation
  final type VerifierComputation = SigmaDJProductVerifierComputation

}
