
# Fuzzing nginx

I started out by just following the oss-fuzz recipe for fuzzing nginx: https://github.com/google/oss-fuzz/tree/master/projects/nginx/ , but there are a couple of problems with the oss-fuzz fuzzer. For example to start out, it uses libprotobuf mutator for some odd reason. I don't really know why the fuck they use libprotobuf mutator, when you can just use the default libfuzzer mutator instead.

I tried compiling the libprotobuf mutator from source, but I got plenty of errors and I gave up. I am going to just change the source code to instead use the default stuff instead.

Here is my fuzzer source (for now):





## Writing the configuration

Now that we have compiled nginx with all of the modules enabled, we now want to enable all of these modules in the configuration file and see what happens.






