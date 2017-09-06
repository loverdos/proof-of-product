name := "proof-of-product"

publishMavenStyle in ThisBuild := true

publishArtifact in Test := false

version := "0.99"

scalaVersion := "2.12.2"

val akkaVersion = "2.5.3"
val logbackVersion = "1.2.3"
val bcVersion = "1.58"
val scalaTestVersion = "3.0.1"
val scalaCheckVersion = "1.13.4"


libraryDependencies ++= Seq(
  "com.typesafe.akka" %% "akka-actor" % akkaVersion,
  "com.typesafe.akka" %% "akka-slf4j" % akkaVersion,

  "ch.qos.logback"   % "logback-classic" % logbackVersion,
  "org.bouncycastle" % "bcprov-jdk15on"  % bcVersion,

  "org.scalatest"     %% "scalatest"    % scalaTestVersion  % Test,
  "org.scalacheck"    %% "scalacheck"   % scalaCheckVersion % Test,
  "com.typesafe.akka" %% "akka-testkit" % akkaVersion       % Test
)
