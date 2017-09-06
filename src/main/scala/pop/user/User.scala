package pop
package user

import java.math.BigInteger

import akka.actor.{Actor, ActorLogging, ActorRef, FSM}
import edu.biu.scapi.midLayer.asymmetricCrypto.encryption.ScDamgardJurikEnc
import pop.Crypto.CNumber
import pop.broker.{Broker, SigmaProver}
import pop.env.EnvHelper
import pop.user.User.Msg._
import pop.user.User.{Data, State}

object User {

  /**
   * The state of the User actor finite state machine (FSM).
   */
  sealed trait State
  object State {
    // The meaning of each state is straightforward to follow from the state machine
    final case object State0 extends State
    final case object State1 extends State
    final case object State2 extends State
    final case object Sigma0 extends State
    final case object Sigma1 extends State
    final case object Final extends State
  }

  /**
   * The data associated with each state in the FSM.
   */
  sealed trait Data
  object Data {
    final case object State0Data extends Data
    final case object State1Data extends Data
    final case class State2Data(userCN: CNumber, otherCN: CNumber) extends Data

    final case class Sigma0Data(userCN: CNumber, otherCN: CNumber, cProduct: CNumber) extends Data
    final case class Sigma1Data(sigma0Data: Sigma0Data, msg1: Sigma.Msg, challenge: Array[Byte]) extends Data

    final case object FinalData extends Data
  }

  /**
   * The message type that the user actor handles.
   */
  sealed trait Msg
  object Msg {
    // sender: broker
    // reason: to ask for the user's number
    final case object WhatIsYourNumber_? extends Msg

    // sender: broker
    // reason: to announce the encrypted numbers of the two users participating in the interaction
    // By convention, the first encrypted number corresponds to the receiver
    final case class AnnounceCNumbers(userCN: CNumber, otherCN: CNumber) extends Msg

    // sender: broker
    // reason: to announce the encrypted product
    final case class AnnounceCProduct(cProduct: CNumber, sigmaProver: ActorRef) extends Msg

    // sender: broker
    // reason: This is the 1st prover message from the SigmaProduct protocol
    final case class SigmaProductProverMsg1(msg: Sigma.Msg) extends Msg

    // sender: broker
    // reason: This is the 2nd prover message from the SigmaProduct protocol
    final case class SigmaProductProverMsg2(msg: Sigma.Msg) extends Msg

    final case object FinalMsg extends Msg

    // These are messages used in testing
    // The use-case is not generalized to other actors but it is straightforward to do so.
    //
    // @see [[pop.ActorTest]]
    sealed trait TestMsg extends Msg
    object Test {
      final case object WhatIsYourState_? extends TestMsg
      final case class MyStateIs(state: State) extends TestMsg
    }
  }
}

class User(
  env: ActorRef,
  n: BigInteger,
  protocolParams: ProtocolParams
) extends Actor with ActorLogging with /*Logging*/FSM[State, Data] with EnvHelper {
  import User.Data._
  import User.State._

  private[this] val challengeLength = protocolParams.soundness / 8

  require(challengeLength > 0, "Challenge length too small. Please adjust the protocol soundness parameter")

  private[this] val encScheme = {
    val encScheme = new ScDamgardJurikEnc(protocolParams.random)
    encScheme.setKey(protocolParams.publicKey)
    encScheme
  }

  private[this] val cN = Crypto.djEncrypt(encScheme, n)

  protected def _env: ActorRef = env

  startWith(State0, State0Data)

  ////////////////////////////////////////////////
  //                        cN
  // Protocol Step 2: user ----> broker
  ////////////////////////////////////////////////
  when(State0) {
    case Event(event @ WhatIsYourNumber_?, State0Data) ⇒
      envInteraction(event)

      goto(State1)
        .using(State1Data)
        .replying(Broker.Msg.ThisIsMyEncryptedNumber(self, cN))
  }

  ////////////////////////////////////////////////
  //                        cA, cB (re-encrypted?)
  // Protocol Step 4: user --------> broker
  ////////////////////////////////////////////////
  when(State1) {
    case Event(AnnounceCNumbers(`cN`, otherCN), State1Data) ⇒
      envInteraction(s"Numbers: ${cN.getCipher}, ${otherCN.getCipher}")

      // NOTE Why (according to the protocol spec) do we have to re-encrypt?
      // TODO? Do the actual re-encryption. For now, just send them as they are

      goto(State2)
        .using(State2Data(cN, otherCN))
        .replying(Broker.Msg.AnnounceCNumbers(cN, otherCN))
  }

  /////////////////////////////////////////////////
  // Sigma Protocol: Start protocol
  ////////////////////////////////////////////////
  when(State2) {
    case Event(AnnounceCProduct(cProduct, sigmaProver), State2Data(`cN`, otherCN)) ⇒
      envInteraction(s"Product: ${cProduct.getCipher}")
      // Got the product, let someone prove it!
      // This "someone" is the sigmaProver, taking over from the broker
      sigmaProver ! SigmaProver.Msg.SigmaProductStart(cN, otherCN, cProduct)

      goto(Sigma0)
        .using(Data.Sigma0Data(cN, otherCN, cProduct))
  }

  /////////////////////////////////////////////////
  // Sigma Protocol: Calculate verifier challenge
  ////////////////////////////////////////////////
  when(Sigma0) {
    case Event(SigmaProductProverMsg1(msg1), sigma0Data @ Sigma0Data(`cN`, otherCN, cProduct)) ⇒
      envInteraction(s"Prover Message 1")

      val challenge = new Array[Byte](challengeLength)
      protocolParams.random.nextBytes(challenge)

      goto(Sigma1)
        .using(Sigma1Data(sigma0Data = sigma0Data, msg1, challenge))
        .replying(SigmaProver.Msg.SigmaProductVerifierChallenge(challenge))
  }

  /////////////////////////////////////////////////
  // Sigma Protocol: Verifier check
  ////////////////////////////////////////////////
  when(Sigma1) {
    case Event(SigmaProductProverMsg2(msg2), Sigma1Data(Sigma0Data(c1, c2, c3), msg1, challenge)) ⇒
      envInteraction(s"Prover Message 2")

      val ci: Sigma.CommonInput = new Sigma.CommonInput(
        protocolParams.publicKey,
        c1,
        c2,
        c3
      )

      val vc = new Sigma.VerifierComputation(
        protocolParams.soundness,
        protocolParams.length,
        protocolParams.random
      )
      vc.setChallenge(challenge) // NOTE Why this API for the challenge?

      val verified = vc.verify(ci, msg1, msg2)

      envConclusion(verified, 1)

      self ! FinalMsg

      goto(Final)
        .using(FinalData)
        .replying(SigmaProver.Msg.SigmaTerminate)
  }

  when(Final) {
    case Event(FinalMsg, FinalData) ⇒
      stop()
  }

  onTransition {
    case from -> to ⇒ envStateChange(from, to)
  }

  val envForwarder: PartialFunction[Any, Any] = {
    case m: User.Msg ⇒
      envRawInteraction(m)
      m

    case m: AnyRef ⇒
      envRawUnexpectedInteraction(m)
      m
  }

  val stateInquiry: PartialFunction[Any, Any] = {
    case m @ User.Msg.Test.WhatIsYourState_? ⇒
      envStateInquiry(stateName)
      sender() ! User.Msg.Test.MyStateIs(stateName)
      m

    case m ⇒ m
  }

  initialize()

  override def receive: Receive =
    envForwarder andThen stateInquiry andThen super.receive
}



