Reasonably documented Proof-of-product.

Given two actors ("users"), each one with an integer that they keep secret, a third actor ("broker") computes the product of the two integers. The users verify the correctness of the computation. Nothing is revealed; only encrypted material is exchanged.

Please start from [Main](src/main/scala/pop/Main.scala).

Tests are [here](src/test/scala/pop/DJSpec.scala) and [here](src/test/scala/pop/UserSpec.scala)

We assume `sbt` is installed (I used `0.13.x`). 
Then `sbt run` runs a sample interaction according to the protocol
and `sbt test` runs the tests.
