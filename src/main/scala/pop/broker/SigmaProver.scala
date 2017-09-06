package pop
package broker

import akka.actor.{Actor, ActorLogging, ActorRef, FSM, PoisonPill}
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey
import edu.biu.scapi.midLayer.plaintext.BigIntegerPlainText
import pop.Crypto.{CNumber, Number}
import pop.broker.SigmaProver.{Data, State}
import pop.env.EnvHelper
import pop.user.User

object SigmaProver {
  // SAMPLEd random values.
  private[broker] final case class SigmaParams(d: BigInt = 0, rd: BigInt = 0, rdb: BigInt = 0)

  private[broker] sealed trait State

  private[broker] object State {
    // The meaning of each state is straightforward to follow from the state machine
    case object State0 extends State
    case object State1 extends State
    case object State2 extends State
  }

  private[broker] sealed trait Data
  private[broker] object Data {
    case object State0Data extends Data

    case class State1Data(
      x1: Number, c1: CNumber,
      c2: CNumber,
      c3: CNumber,
      msg1: Sigma.Msg
    ) extends Data

    case class State2Data(
      state1Data: State1Data,
      msg2: Sigma.Msg
    ) extends Data
  }

  sealed trait Msg
  object Msg {
    // sender: user
    // reason: prove this is indeed the product
    //final case class ProveMeYouAreWorthIt(senderCN: CNumber, otherCN: CNumber, cProduct: CNumber)

    // OK the above was a funny name. Let's use another one
    final case class SigmaProductStart(senderCN: CNumber, otherCN: CNumber, cProduct: CNumber) extends Msg

    // sender: user
    // reason: This is the challenge message from the SigmaProduct protocol
    final case class SigmaProductVerifierChallenge(challenge: Array[Byte]) extends Msg

    // sender: user
    // reason: to terminate the sigma protocol
    final case object SigmaTerminate extends Msg
  }
}

/**
 * Implements the prover part of the corresponding Sigma protocol.
 * We reuse as much as we can from the SCAPI project.
 *
 */
class SigmaProver private[broker](
  env: ActorRef,
  protocolParams: ProtocolParams,
  privateKey: DamgardJurikPrivateKey,
  userInfo: UserInfo,
  otherUserInfo: UserInfo,
  c: Number,
  cC: CNumber
) extends BrokerCommon(protocolParams, privateKey) with Actor with ActorLogging with /*Logging*/FSM[State, Data] with EnvHelper {

  import SigmaProver.Data._
  import SigmaProver.Msg._
  import SigmaProver.State._

  // Let's just reuse what we have
  private[this] val pc = new Sigma.ProverComputation(
    protocolParams.soundness,
    protocolParams.length,
    protocolParams.random
  )

  protected def _env: ActorRef = env

  startWith(State0, State0Data)

  /////////////////////////////////////////////////
  // Sigma Protocol: Calculate prover message 1
  ////////////////////////////////////////////////
  when(State0) {
    case Event(SigmaProductStart(senderCN, otherCN, cProduct), State0Data) ⇒
      envInteraction("Protocol started")

      val c1 = senderCN
      val c2 = otherCN
      val c3 = cProduct

      val x1 = djDecryptF(c1)
      val x2 = djDecryptF(c2)

      val pi = new Sigma.ProverInput(
        protocolParams.publicKey,
        c1,
        c2,
        c3,
        privateKey,
        new BigIntegerPlainText(x1),
        new BigIntegerPlainText(x2)
      )

      val msg1: Sigma.Msg = pc.computeFirstMsg(pi)

      goto(State1)
        .using(State1Data(x1 = x1, c1 = c1, c2 = c2, c3 = c3, msg1 = msg1))
        .replying(User.Msg.SigmaProductProverMsg1(msg1))
  }

  /////////////////////////////////////////////////
  // Sigma Protocol: Calculate prover message 2
  ////////////////////////////////////////////////
  when(State1) {
    case Event(SigmaProductVerifierChallenge(challenge), dataState1 @ State1Data(x1, c1, c2, c3, msg2)) ⇒
      envInteraction("Challenge accepted")

      val msg2: Sigma.Msg = pc.computeSecondMsg(challenge)

      goto(State2)
        .using(State2Data(state1Data = dataState1, msg2 = msg2))
        .replying(User.Msg.SigmaProductProverMsg2(msg2))
  }

  when(State2) {
    case Event(SigmaTerminate, _) ⇒
      stop()
  }

  onTransition {
    case from -> to ⇒ envStateChange(from, to)
  }

  val envForwarder: PartialFunction[Any, Any] = {
    case m: SigmaProver.Msg ⇒
      envRawInteraction(m)
      m

    case m: AnyRef ⇒
      envRawUnexpectedInteraction(m)
      m
  }

  initialize()

  override def receive: Receive = envForwarder andThen super.receive
}

