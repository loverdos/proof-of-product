package pop
import java.math.BigInteger
import java.security.SecureRandom

import org.scalatest.prop.GeneratorDrivenPropertyChecks
import org.scalatest.{Matchers, PropSpec}

/**
 * Tests related to the SCAPI library.
 */
class DJSpec extends PropSpec with GeneratorDrivenPropertyChecks with Matchers {
  val random = new SecureRandom()
  val (djScheme, DJKeyPair(publicKey, privateKey)) = Crypto.newDJScheme(random)

  // This test or a similar one should be in the original library
  // so one might think it is redundant.
  // In reality it helps understand SCAPI both as an API
  // and operationally.
  //
  // Actually, I have written this code while developing some
  // functions in [[pop.Crypto]], thus practicing TDD.
  //
  // ... and the following was an interesting outcome (slightly reformatted) ...
  // [info] DJSpec:
  // [info] - DJ scheme encrypts/decrypts as expected *** FAILED ***
  // [info]   TestFailedException was thrown during property evaluation.
  // [info]     Message: 8636471617721434036239134509759053647149099640242482558248575588307427387753893433732378753417011232720574542199830366674112642154348376843323412257305280220744777936230133317001013080978347868374852813819043918311619371149058443829162975903349144696700746447423041777752193717264364408069364723116388972019792696389619472936352311720112014088786683541657969850212763073416134004405430729657745713232640495056214935969998723535743935003432356033696732120755086020169605917660188041790355888630299777467805626348354929760305308029956577753040325638130135177001165921626052467802327639265001927155438587447594323795528
  //            was not equal to 1
  // [info]     Location: (DJSpec.scala:31)
  // [info]     Occurred when passed generated values (
  // [info]       arg0 = 1 // 2 shrinks
  // [info]     )
  //
  //
  // ... and another one ...
  //
  // [info] DJSpec:
  // [info] - DJ scheme encrypts <--> decrypts as expected *** FAILED ***
  // [info]   TestFailedException was thrown during property evaluation.
  // [info]     Message: 20089692438566240054766952226680368887153456816760717876423068376859302911565914314814523113153991761083138857367768577654091560509197569088943307754976066240675872518097497605026675506239734890836985648246599763339564626269466467836647452848214779795644430355307980270341015152391302647944763261970166461061831911725833999483433210972614583085372598333879289165202249647932730783426534658873137097544524252708208114064217849863199598624759095330483710365653524628633572712508751990203264610223006042954369897849862356195201698533875460610261916079788597061565522636198807785902517974124317363059990192681651154208605
  //            was not equal to 10
  // [info]     Location: (DJSpec.scala:41)
  // [info]     Occurred when passed generated values (
  // [info]       arg0 = 10 // 25 shrinks
  // [info]     )

  property("DJ scheme encrypts <--> decrypts as expected") {
    forAll { (l: Long) ⇒
      whenever( l > 0) {
        val original = BigInteger.valueOf(l)

        val cN = Crypto.djEncrypt(djScheme, original)
        val n = Crypto.djDecrypt(djScheme, cN)

        n shouldBe original
      }
    }
  }
}
