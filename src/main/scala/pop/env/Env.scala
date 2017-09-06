package pop.env

import akka.actor.{Actor, ActorRef, ActorSystem, Props}
import pop.Main.EnvName
import pop.env.Env.Msg._

object Env {
  final val DefaultPrinter: (String) ⇒ Unit = System.err.println(_:String)

  def apply(system: ActorSystem, printer: (String) ⇒ Unit = DefaultPrinter): ActorRef =
    system.actorOf(Props(classOf[Env], printer), EnvName)

  sealed trait Msg
  object Msg {
    // An interaction between two actors with the actual (raw) message.
    // This is normally triggered automatically.
    // Contrast with the following, whose role is to be less verbose.
    final case class RawInteraction(from: ActorRef, to: ActorRef, msg: AnyRef) extends Msg

    // An unexpected (=outside the protocol) interaction between two actors with the actual (raw) message.
    final case class RawUnexpectedInteraction(from: ActorRef, to: ActorRef, msg: AnyRef) extends Msg

    // An interaction between two actors, reported by the recipient.
    // The `msg` parameter need not be the actual message but a semantic abbreviation (=less verbose).
    final case class Interaction(from: ActorRef, to: ActorRef, msg: AnyRef) extends Msg

    // A user's conclusion regarding the Sigma protocol
    final case class Conclusion(
      user: ActorRef,
      verified: Boolean,
      attempts: Int /* a user only attempts once for now ...*/
    ) extends Msg

    // A state change of an actor that participates in a protocol
    final case class StateChange(actor: ActorRef, from: AnyRef, to: AnyRef) extends Msg

    // Someone asks about the state of an (FSM) actor
    final case class StateInquiry(from: ActorRef, about: ActorRef, state: AnyRef) extends Msg

    final case class ReportTimeout(from: ActorRef, atState: AnyRef, timeoutMsg: AnyRef) extends Msg
  }
}

/**
 * The "environment" actor that keeps track of what is going on between Alice, Bob and Carroll the broker.
 */
class Env(printer: (String) ⇒ Unit) extends Actor {
  def n(r: ActorRef): String = r.path.name
  def p(x: String): Unit = printer(s"ENV $x")

  // Some nice private mutable state.
  // Could do without it but it's a simple case and we only need this small piece of state.
  // As a 1st approximation, we track only the number of conclusions, not who sent them,
  // if there are duplicate conclusions etc.
  //
  // @see [[pop.env.Env.Msg.Conclusion]]
  private var _conclusions = 0

  def terminate(): Unit = context.system.terminate()

  def receive: Receive = {
    case m @ RawInteraction(from, to, msg) ⇒
      p(s"RAW (${n(from)}, ${n(to)}, $msg)")

    case m @ RawUnexpectedInteraction(from, to, msg) ⇒
      p(s"RAW UNEXPECTED (${n(from)}, ${n(to)}, $msg)")

    case m @ Interaction(from, to, msg) ⇒
      p(s"[${m.productPrefix}] '${n(from)}' -> '${n(to)}': $msg")

    case m @ Conclusion(user, verified, attempts) ⇒
      val s_verified = if(verified) "Accept" else "Reject"
      p(s"[${m.productPrefix}] '${n(user)}': ${s_verified} [$attempts]")

      _conclusions += 1
      if(_conclusions == 2) {
        terminate()
      }

    case m @ StateChange(actor, from, to) ⇒
      p(s"[${m.productPrefix}] '${n(actor)}': ${from} -> ${to}")

    case m @ StateInquiry(from, about, state) ⇒
      p(s"[${m.productPrefix}] '${n(from)}' about '${n(about)}':  $state")

    case m @ ReportTimeout(from, state, msg) ⇒
      p(s"[${m.productPrefix}] for '${n(from)}' at state '$state' [$msg]")

    case m ⇒
      // This is a message unknown to the Env.
      // Contrast this case with `RawUnexpectedInteraction` messages
      p(s"UNKNOWN message $m")
  }
}
