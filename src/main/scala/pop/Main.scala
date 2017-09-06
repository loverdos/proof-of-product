package pop

import java.security.SecureRandom

import akka.actor.{ActorSystem, Props}
import pop.broker.Broker
import pop.env.Env
import pop.user.User

import scala.concurrent.duration.{DurationInt, FiniteDuration}

/**
 * The main app.
 * There is reasonable (= realistic) documentation along the major code paths.
 *
 * Just do an
 *
 * {{{
 *   sbt run
 * }}}
 *
 * or
 * {{{
 *   sbt test
 * }}}
 *
 * in a shell, from the project folder.
 */
object Main {
  // NOTE that the names must be unique in the actor system
  // This helped me find a protocol bug where duplicate SigmaProver actors where created :)
  final val EnvName = "Env"
  final val AliceName = "Alice"
  final val BobName = "Bob"
  final val BrokerName = "Broker"

  def main(args: Array[String]): Unit = {
    val random = new SecureRandom()
    val djKeyPair = Crypto.newDJKeyPair(random)

    val publicKey = djKeyPair.publicKey
    val privateKey = djKeyPair.privateKey

    val A_ = Crypto.createRandomInRange(0, 1000000, random)
    val B_ = Crypto.createRandomInRange(0, 1000000, random)

    val A = A_.bigInteger
    val B = B_.bigInteger

    val protocolParams = ProtocolParams(length = 1, soundness = 20, random = random, publicKey = publicKey)

    val timeout: FiniteDuration = 10.seconds

    // The actors are instantiated in order to participate in just one interaction (just run the protocol).
    val system = ActorSystem("proof-of-product")

    val env = Env(system)

    // Initially, a user knows only their number and the public key.
    val alice = system.actorOf(Props(classOf[User], env, A, protocolParams), AliceName)
    val bob   = system.actorOf(Props(classOf[User], env, B, protocolParams), BobName)

    val broker = system.actorOf(Props(classOf[Broker], env, protocolParams, privateKey, timeout), BrokerName)

    broker ! Broker.Msg.InitInteraction(alice, bob)

    // Just watch the messages flow from the environment
    // When both users send their conclusion messages to the environment,
    // the interaction (actually the actor system) will terminate.
  }
}
