package pop
package broker

import akka.actor.{Actor, ActorLogging, ActorRef, FSM, PoisonPill, Props}
import edu.biu.scapi.midLayer.asymmetricCrypto.keys.DamgardJurikPrivateKey
import pop.Crypto.{CNumber, Number}
import pop.broker.Broker.Msg._
import pop.broker.Broker.{Data, State}
import pop.env.EnvHelper
import pop.user.User

import scala.concurrent.duration.FiniteDuration

object Broker {

  private[broker] sealed trait State
  private[broker] object State {

    // The meaning of each state is straightforward to follow from the state machine

    case object State0 extends State
    case object State1 extends State
    case object State2 extends State
    case object Final extends State
  }

  private[broker] sealed trait Data

  private[broker] object Data {
    case object State0Data extends Data
    case object State3Data extends Data
    case class State1Data(
      alice: ActorRef, // NOTE could generalize the two ActorRef fields to a Set[ActorRef]
      bob: ActorRef,
      aliceInfo: Option[(Number, CNumber)] = None,
      bobInfo: Option[(Number, CNumber)] = None
    ) extends Data {

      def isFull: Boolean = aliceInfo.isDefined && bobInfo.isDefined
    }

    case class State2Data(
      aliceInfo: UserInfo,
      bobInfo: UserInfo,
      cNumberCount: Int // how many cNumbers have been announced. min = 0, max = 2
    ) extends Data {

      def incCNumberCount: State2Data = copy(cNumberCount = cNumberCount + 1)
    }

    case object FinalData extends Data
  }

  sealed trait Msg

  object Msg {
    // sender: application
    // reason: to initiate the interaction protocol
    final case class InitInteraction(alice: ActorRef, bob: ActorRef) extends Msg

    // sender: user
    // reason: respond to `UserMsg.WhatIsYourNumber_?`
    final case class ThisIsMyEncryptedNumber(user: ActorRef, cN: CNumber) extends Msg

    // sender: user
    // reason: to announce the encrypted numbers of the two users participating in the interaction
    // By convention, the first encrypted number corresponds to the sender
    final case class AnnounceCNumbers(senderCN: CNumber, otherCN: CNumber) extends Msg

    // sender: user
    // reason: to initiate a proof protocol (sigma)
    final case object RequestProof extends Msg

    private[broker] final case object Timeout extends Msg

    private[broker] final case object FinalMsg extends Msg
  }
}

class Broker(
  env: ActorRef,
  protocolParams: ProtocolParams,
  privateKey: DamgardJurikPrivateKey,
  timeout: FiniteDuration
) extends BrokerCommon(protocolParams, privateKey) with Actor with ActorLogging with /*Logging*/FSM[State, Data] with EnvHelper {

  import Broker.Data._
  import Broker.State._

  protected def _env: ActorRef = env

  startWith(State0, State0Data)

  ////////////////////////////////////////////////
  // Protocol Step 1: broker -> alice, bob
  ////////////////////////////////////////////////
  when(State0) {
    // We define the protocol for a pair of distinct users (first approximation: alice != bob)
    case Event(InitInteraction(alice, bob), State0Data) if alice != bob ⇒
      envInteraction("Initial state")

      alice ! User.Msg.WhatIsYourNumber_?
      bob   ! User.Msg.WhatIsYourNumber_?

      // Set the timeout for receiving both encrypted numbers.
      // This is checked at the next state, State1
      context.system.scheduler.scheduleOnce(timeout, self, Timeout)((context.dispatcher))

      goto(State1)
        .using(State1Data(alice, bob))
  }

  // We remain at State1Data until we have numbers from both Alice and Bob.
  private[this] def computeState1Next(updatedState1Data: State1Data): FSM.State[Broker.State, Broker.Data] = {
    val aliceInfo = updatedState1Data.aliceInfo
    val bobInfo = updatedState1Data.bobInfo
    (aliceInfo, bobInfo) match {
      case (Some((a, cA)), Some((b, cB))) ⇒
        val alice = updatedState1Data.alice
        val bob = updatedState1Data.bob

        // Announce the encrypted numbers
        alice ! User.Msg.AnnounceCNumbers(cA, cB)
        bob   ! User.Msg.AnnounceCNumbers(cB, cA)

        // Set a timeout waiting for numbers to come back from both users.
        // This is checked at the next state, State2 (this enclosing helper function is for State1)
        // NOTE we use the same timeout everywhere, it could be different per use-case
        context.system.scheduler.scheduleOnce(timeout, self, Timeout)(context.dispatcher)

        // proceed to the next state
        log.info("Got everything, proceeding to State2")
        goto(State2)
          .using(
            State2Data(
              aliceInfo = UserInfo(alice, a, cA),
              bobInfo = UserInfo(bob, b, cB),
              cNumberCount = 0
            )
          )

      case _ ⇒
        // remain at the same state but with the updated data
        log.info("Staying at Stage1")
        stay().using(updatedState1Data)
    }
  }

  ////////////////////////////////////////////////
  //                          cA, cB
  // Protocol Step 3: broker --------> alice, bob
  ////////////////////////////////////////////////
  when(State1) {
    case Event(event @ Timeout, State1Data(alice, bob, _, _)) ⇒
      // Timeout occurred before receiving both encrypted numbers.
      envTimeout(stateName, event)
      alice ! PoisonPill
      bob ! PoisonPill
      stop()

    case Event(ThisIsMyEncryptedNumber(user, cN), state1Data @ State1Data(alice, bob, _, _)) if user == alice ⇒
      envInteraction(s"cA = ${cN.getCipher}")

      val n = djDecryptF(cN)
      val updatedData = state1Data.copy(aliceInfo = Some(n, cN))

      computeState1Next(updatedData)

    case Event(ThisIsMyEncryptedNumber(user, cN), state1Data @ State1Data(_, bob, _, _)) if user == bob ⇒
      envInteraction(s"cB = ${cN.getCipher}")

      val n = djDecryptF(cN)
      val updatedData = state1Data.copy(bobInfo = Some(n, cN))

      computeState1Next(updatedData)
  }

  /////////////////////////////////////////////////
  //                          cC
  // Protocol Step 5: broker ----> user
  ////////////////////////////////////////////////
  when(State2) {
    case Event(event @ Timeout, State2Data(aliceInfo, bobInfo, cNumberCount)) ⇒
      // Timeout occurred before receiving both encrypted numbers.
      envTimeout(stateName, event)
      aliceInfo.actor ! PoisonPill
      bobInfo.actor ! PoisonPill
      stop()

    // The broker gets two of these events, so we track them using `cNumberCount`
    // The valid, according to the protocol, values for `cNumberCount` are: 0, 1
    case Event(event @ AnnounceCNumbers(senderCN, otherCN), state2Data @ State2Data(aliceInfo, bobInfo, cNumberCount)) if Set(0, 1)(cNumberCount) ⇒
      def isAlice = aliceInfo.actor == sender()
      def isBob = bobInfo.actor == sender()

      // Calculate C
      val maybeA = djDecryptF(senderCN)
      val maybeB = djDecryptF(otherCN)
      val c_ = BigInt(maybeA) * BigInt(maybeB)
      val c = c_.bigInteger
      val cC = djEncryptF(c)

      // Broker spawns one SigmaProver actor per user, so that
      //   a) Each user proceeds independently (one user may be more easily convinced than another one)
      //   b) Sigma protocol state tracking at the broker (=SigmaProver) site is handled for each user independently.
      //
      // So, in effect, a Broker has two personalities:
      //   1. "Computer" for the product computation
      //   2. "Prover" for running the sigma protocol as a Prover
      //
      // A SigmaProver is trusted to the Broker, since it receives its private key.
      //
      // NOTE It is interesting to generalize this separation of concerns at the User side
      //      of the protocol/interaction as well, towards a generic actor-based sigma protocol interaction.

      def newSigmaProver(name: String, myInfo: UserInfo, otherInfo: UserInfo): ActorRef =
        context.system.actorOf(
          Props(
            classOf[SigmaProver],
            env,
            protocolParams, privateKey,
            myInfo, otherInfo,
            c, cC
          ),
          name
        )

      def proceed(): FSM.State[Broker.State, Broker.Data] =
        if(cNumberCount == 0) {
          // One CNumber was announced, so we track this in the state data.
          stay().
            using(state2Data.incCNumberCount)
        }
        else {
          // The second CNumber announced
          self ! FinalMsg
          goto(Final)
            .using(FinalData)
        }

      if(isAlice) {
        envInteraction(s"Alice sent c1, c2")

        val aliceSigma = newSigmaProver("SigmaProver_Alice", aliceInfo, bobInfo)

        aliceInfo.actor ! User.Msg.AnnounceCProduct(cC, aliceSigma)

        proceed()
      }
      else if(isBob) {
        envInteraction(s"Bob sent c1, c2")

        val bobSigma = newSigmaProver("SigmaProver_Bob", bobInfo, aliceInfo)

        bobInfo.actor ! User.Msg.AnnounceCProduct(cC, bobSigma)

        proceed()
      }
      else {
        envInteraction(s"Unexpected: $event")

        // Error!
        // TODO inform the environment actor
        stop()
      }

  }

  when(Final) {
    case Event(FinalMsg, FinalData) ⇒
      stop()
  }

  onTransition {
    case from -> to ⇒ envStateChange(from, to)
  }

  val envForwarder: PartialFunction[Any, Any] = {
    case m: Broker.Msg ⇒
      envRawInteraction(m)
      m

    case m: AnyRef ⇒
      envRawUnexpectedInteraction(m)
      m
  }

  initialize()

  override def receive: Receive = envForwarder andThen super.receive
}
