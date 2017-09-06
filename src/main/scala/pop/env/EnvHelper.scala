package pop.env

import akka.actor.{Actor, ActorRef}
import pop.env.Env.Msg._

trait EnvHelper { actor: Actor ⇒
  protected def _env: ActorRef

  protected def envInteraction(data: AnyRef): Unit =
    _env ! Interaction(sender(), actor.self , data)

  protected def envRawInteraction(rawMsg: AnyRef): Unit =
    _env ! RawInteraction(sender(), actor.self, rawMsg)

  protected def envRawUnexpectedInteraction(rawMsg: AnyRef): Unit =
    _env ! RawUnexpectedInteraction(sender(), actor.self, rawMsg)

  protected def envStateChange(from: AnyRef, to: AnyRef): Unit =
    _env ! StateChange(actor.self, from, to)

  protected def envConclusion(verified: Boolean, attempts: Int): Unit =
    _env ! Conclusion(actor.self, verified, attempts)

  protected def envStateInquiry(state: AnyRef): Unit =
    _env ! StateInquiry(sender(), actor.self, state)

  protected def envTimeout(atState:AnyRef, msg: AnyRef): Unit =
    _env ! ReportTimeout(sender(), atState, msg)
}
