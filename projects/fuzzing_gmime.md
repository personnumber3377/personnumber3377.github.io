
# Fuzzing gmime

Gmime is a library which is used to parse email files as per https://www.ietf.org/rfc/rfc2822.txt . I decided to run a fuzzing campaign against it and see what we can find... There doesn't appear to be any fuzzers for this library in the source code. There are unittests, but there are no fuzzers, so I think that we have a good change of finding bugs.

## Results
