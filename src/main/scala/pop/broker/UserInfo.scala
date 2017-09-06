package pop.broker

import akka.actor.ActorRef
import pop.Crypto.{CNumber, Number}

final case class UserInfo(
  actor: ActorRef,
  n: Number, // the user's number
  cN: CNumber// the user's encrypted number
)
