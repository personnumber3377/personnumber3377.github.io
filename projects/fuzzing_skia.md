# Fuzzing skia shaders

I have fuzzed GLSL shaders in the past and it didn't really produce any results (meaning no bugs), however there is this library called skia which is responsible for handling the 2D rendering operations in for example the android operating system and google chrome and such.

There has recently been vulnerabilities related to skias own shader language called SkSl (skia shader language) which is syntactically very similar to GLSL. The plan is to adapt my existing corpus and mutator for this new target to hopefully shake out some bugs out of it.

## Setting up the target

Ok, so there are existing fuzzers in skia for example the sksl2pipeline fuzzer which I enabled and built in the chromium source tree...

Then we need to somehow wire our python custom mutator to the fuzzer.

