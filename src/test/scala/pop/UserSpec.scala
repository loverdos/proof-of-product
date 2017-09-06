package pop

import java.math.BigInteger
import java.security.SecureRandom

import akka.actor.{ActorRef, ActorSystem, Props}
import akka.testkit.{ImplicitSender, TestKit}
import org.scalatest.{BeforeAndAfterAll, Matchers, WordSpecLike}
import pop.broker.Broker
import pop.env.Env
import pop.user.User

import scala.concurrent.duration.DurationInt

object UserSpec {
  final val System = ActorSystem("pop-test")
}

class UserSpec extends TestKit(UserSpec.System)
  with WordSpecLike with Matchers with BeforeAndAfterAll with ImplicitSender {

  override protected def afterAll(): Unit = shutdown()

  var _counter = 0
  def nextCounter: Int = {
    val counter = _counter
    _counter += 1
    counter
  }

  val env = Env(system)

  val random = new SecureRandom()
  val (djScheme, DJKeyPair(publicKey, privateKey)) = Crypto.newDJScheme(random)
  val protocolParams = ProtocolParams(length = 1, soundness = 20, random = random, publicKey = publicKey)

  def randomNumber(): BigInt = Crypto.createRandomInRange(0, 1000000, random)

  def createAlice(): (BigInteger, ActorRef) = {
    val n = randomNumber().bigInteger
    val alice = system.actorOf(Props(classOf[User], env, n, protocolParams), s"${Main.AliceName}_${nextCounter}")

    (n, alice)
  }

  // Testing revealed this failure case (slightly reformatted, line numbers are from the code before inserting this comment):
  /////////////////////////////////////////
  // [info] UserSpec:
  // [info] - Alice responds correctly to WhatIsYourNumber_? *** FAILED ***
  // [info]   12233360597261414795553704354275169796703756958551186149316807561089157106209538866079500263320539486442398153061339145850929293082923544784513886496365294073834788396645775678557518392047696342552991829749951996616009164536020405206519229884857286266864747553980338328328121882491491749428443246721235902477511696689577383858224382132960129323072972671386326731339153571991583316423054076502284567027897712319156138268043242367835682106865383174491510553948788947890272366434869529656551785298473779831686071513945767911254463862666602027406150428969649163664948699461953797148662283534942137028080477900549047258735
  //          was not equal to 736452 (UserSpec.scala:61)
  /////////////////////////////////////////
  //
  // ... and another one ...
  /////////////////////////////////////////
  //[info] UserSpec:
  //[info] - Alice responds correctly to WhatIsYourNumber_? *** FAILED ***
  //[info]   2970055418086486478378667409947384562008117993224024129110075647702167229750171363551704249731071575618443871217381466226924092862435469432522116781093899972204077560937905519545274928526544881142930428829911616041640307856237241609282630889287816769961547353693165396451972896433005719289970871235654934737850779296018521426862919770321530793225608168937939332469542984028914285688620437624663901110705716508111938791877365858139306074190603625856444415293308686143088686861156227179146469523499121325775002676998193293773468853871608255763385920477067436151270938230559227010285617943753922169340894099745549431880
  //         was not equal to 339648 (UserSpec.scala:68)
  /////////////////////////////////////////

  "Alice responds correctly to WhatIsYourNumber_?" in {
    val (n, alice) = createAlice()

    // We emulate the broker here
    alice ! User.Msg.WhatIsYourNumber_?

    // NOTE 3 seconds sounds like enough, although a good approximation should probably
    //      be discovered *after* running/simulating the whole procedure.
    val maxDuration = 3.seconds

    val Broker.Msg.ThisIsMyEncryptedNumber(actor, encrypted) = receiveOne(maxDuration)
    val decrypted = Crypto.djDecrypt(djScheme, encrypted)

    actor shouldBe alice
    decrypted shouldBe n
  }

  "Alice goes from State0 to State1 after WhatIsYourNumber_?" in {
    val (n, alice) = createAlice()

    alice ! User.Msg.WhatIsYourNumber_?
    val maxDuration = 3.seconds
    receiveOne(maxDuration)

    alice ! User.Msg.Test.WhatIsYourState_?
    val User.Msg.Test.MyStateIs(state) = receiveOne(maxDuration)

    state shouldBe User.State.State1
  }
}
