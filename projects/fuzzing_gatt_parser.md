# Fuzzing GATT parser

## Ok, so I got these errors here when trying to compile the thing:

```
 debian/rules build
dh build --parallel
   dh_update_autotools_config
   dh_autoreconf
   debian/rules override_dh_auto_build-arch
make[1]: Entering directory '/tmp/tmp.RoMyEQTYQk/libchrome-1094370'
gn gen out/Release --args="pkg_config=\"pkg-config\" libbase_ver=\"1094370\" platform2_root=\"/tmp/tmp.RoMyEQTYQk/libchrome-1094370/\" platform_subdir=\"libchrome\" cxx=\"clang++\" cc=\"clang\" ar=\"ar\" external_cxxflags=[\"-DNDEBUG\", \"-I/usr/src/googletest/googletest/include\", \"-I/usr/src/googletest/googlemock/include\", \"-Wno-unknown-warning-option\", \"-Wno-unused-command-line-argument\", \"-Wno-implicit-int-float-conversion\"] external_ldflags=[\"-latomic\", \"-labsl_base\", \"-labsl_bad_variant_access\", \"-labsl_bad_optional_access\"] enable_werror=false libdir=\"/usr/lib\" use={mojo=false asan=false msan=false ubsan=false coverage=false crypto=true dbus=true fuzzer=false timers=true cros_host=false cros_debug=false profiling=false tcmalloc=false test=false}"
Done. Made 38 targets from 11 files in 578ms
ninja -j8 -C out/Release
ninja: Entering directory `out/Release'
[61/450] CXX obj/libchrome/base/test/libbase-base_test_support.scoped_run_loop_timeout.o
FAILED: obj/libchrome/base/test/libbase-base_test_support.scoped_run_loop_timeout.o
clang++ -MMD -MF obj/libchrome/base/test/libbase-base_test_support.scoped_run_loop_timeout.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOS_CHROMEOS -DUSE_NSS_CERTS -DUSE_SYSTEM_LIBEVENT -DNO_TCMALLOC -DMOJO_BACKWARDS_COMPAT -DMOJO_CORE_LEGACY_PROTOCOL -Igen/include -I../.. -I/usr/include -I../../libchrome -Igen/libchrome -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wimplicit-int-float-conversion -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough --sysroot= -fPIE -Wno-deprecated-register -Wno-narrowing -Wno-unreachable-code-return -Wno-unused-local-typedefs -Wno-char-subscripts -std=gnu++17 -DNDEBUG -I/usr/src/googletest/googletest/include -I/usr/src/googletest/googlemock/include -Wno-unknown-warning-option -Wno-unused-command-line-argument -Wno-implicit-int-float-conversion -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-psabi -c ../../libchrome/base/test/scoped_run_loop_timeout.cc -o obj/libchrome/base/test/libbase-base_test_support.scoped_run_loop_timeout.o
In file included from ../../libchrome/base/test/scoped_run_loop_timeout.cc:5:
In file included from ../../libchrome/base/test/scoped_run_loop_timeout.h:10:
In file included from ../../libchrome/base/functional/callback.h:21:
../../libchrome/base/functional/function_ref.h:81:38: error: expected ')'
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                     ^
../../libchrome/base/functional/function_ref.h:81:14: note: to match this '('
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
             ^
1 error generated.
[62/450] CXX obj/libchrome/base/test/libbase-base_test_support.test_file_util_posix.o
FAILED: obj/libchrome/base/test/libbase-base_test_support.test_file_util_posix.o
clang++ -MMD -MF obj/libchrome/base/test/libbase-base_test_support.test_file_util_posix.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOS_CHROMEOS -DUSE_NSS_CERTS -DUSE_SYSTEM_LIBEVENT -DNO_TCMALLOC -DMOJO_BACKWARDS_COMPAT -DMOJO_CORE_LEGACY_PROTOCOL -Igen/include -I../.. -I/usr/include -I../../libchrome -Igen/libchrome -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wimplicit-int-float-conversion -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough --sysroot= -fPIE -Wno-deprecated-register -Wno-narrowing -Wno-unreachable-code-return -Wno-unused-local-typedefs -Wno-char-subscripts -std=gnu++17 -DNDEBUG -I/usr/src/googletest/googletest/include -I/usr/src/googletest/googlemock/include -Wno-unknown-warning-option -Wno-unused-command-line-argument -Wno-implicit-int-float-conversion -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-psabi -c ../../libchrome/base/test/test_file_util_posix.cc -o obj/libchrome/base/test/libbase-base_test_support.test_file_util_posix.o
In file included from ../../libchrome/base/test/test_file_util_posix.cc:17:
In file included from ../../libchrome/base/files/file_util.h:24:
In file included from ../../libchrome/base/functional/callback.h:21:
../../libchrome/base/functional/function_ref.h:81:38: error: expected ')'
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                     ^
../../libchrome/base/functional/function_ref.h:81:14: note: to match this '('
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
             ^
1 error generated.
[63/450] CXX obj/libchrome/base/test/libbase-base_test_support.test_mock_time_task_runner.o
FAILED: obj/libchrome/base/test/libbase-base_test_support.test_mock_time_task_runner.o
clang++ -MMD -MF obj/libchrome/base/test/libbase-base_test_support.test_mock_time_task_runner.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOS_CHROMEOS -DUSE_NSS_CERTS -DUSE_SYSTEM_LIBEVENT -DNO_TCMALLOC -DMOJO_BACKWARDS_COMPAT -DMOJO_CORE_LEGACY_PROTOCOL -Igen/include -I../.. -I/usr/include -I../../libchrome -Igen/libchrome -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wimplicit-int-float-conversion -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough --sysroot= -fPIE -Wno-deprecated-register -Wno-narrowing -Wno-unreachable-code-return -Wno-unused-local-typedefs -Wno-char-subscripts -std=gnu++17 -DNDEBUG -I/usr/src/googletest/googletest/include -I/usr/src/googletest/googlemock/include -Wno-unknown-warning-option -Wno-unused-command-line-argument -Wno-implicit-int-float-conversion -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-psabi -c ../../libchrome/base/test/test_mock_time_task_runner.cc -o obj/libchrome/base/test/libbase-base_test_support.test_mock_time_task_runner.o
In file included from ../../libchrome/base/test/test_mock_time_task_runner.cc:5:
In file included from ../../libchrome/base/test/test_mock_time_task_runner.h:15:
In file included from ../../libchrome/base/functional/callback.h:21:
../../libchrome/base/functional/function_ref.h:81:38: error: expected ')'
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                     ^
../../libchrome/base/functional/function_ref.h:81:14: note: to match this '('
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
             ^
1 error generated.
[64/450] CXX obj/libchrome/base/test/libbase-base_test_support.test_file_util.o
FAILED: obj/libchrome/base/test/libbase-base_test_support.test_file_util.o
clang++ -MMD -MF obj/libchrome/base/test/libbase-base_test_support.test_file_util.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOS_CHROMEOS -DUSE_NSS_CERTS -DUSE_SYSTEM_LIBEVENT -DNO_TCMALLOC -DMOJO_BACKWARDS_COMPAT -DMOJO_CORE_LEGACY_PROTOCOL -Igen/include -I../.. -I/usr/include -I../../libchrome -Igen/libchrome -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wimplicit-int-float-conversion -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough --sysroot= -fPIE -Wno-deprecated-register -Wno-narrowing -Wno-unreachable-code-return -Wno-unused-local-typedefs -Wno-char-subscripts -std=gnu++17 -DNDEBUG -I/usr/src/googletest/googletest/include -I/usr/src/googletest/googlemock/include -Wno-unknown-warning-option -Wno-unused-command-line-argument -Wno-implicit-int-float-conversion -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-psabi -c ../../libchrome/base/test/test_file_util.cc -o obj/libchrome/base/test/libbase-base_test_support.test_file_util.o
In file included from ../../libchrome/base/test/test_file_util.cc:10:
In file included from ../../libchrome/base/files/file_util.h:24:
In file included from ../../libchrome/base/functional/callback.h:21:
../../libchrome/base/functional/function_ref.h:81:38: error: expected ')'
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                     ^
../../libchrome/base/functional/function_ref.h:81:14: note: to match this '('
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
             ^
1 error generated.
[65/450] CXX obj/libchrome/base/test/libbase-base_test_support.scoped_feature_list.o
FAILED: obj/libchrome/base/test/libbase-base_test_support.scoped_feature_list.o
clang++ -MMD -MF obj/libchrome/base/test/libbase-base_test_support.scoped_feature_list.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOS_CHROMEOS -DUSE_NSS_CERTS -DUSE_SYSTEM_LIBEVENT -DNO_TCMALLOC -DMOJO_BACKWARDS_COMPAT -DMOJO_CORE_LEGACY_PROTOCOL -Igen/include -I../.. -I/usr/include -I../../libchrome -Igen/libchrome -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wimplicit-int-float-conversion -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough --sysroot= -fPIE -Wno-deprecated-register -Wno-narrowing -Wno-unreachable-code-return -Wno-unused-local-typedefs -Wno-char-subscripts -std=gnu++17 -DNDEBUG -I/usr/src/googletest/googletest/include -I/usr/src/googletest/googlemock/include -Wno-unknown-warning-option -Wno-unused-command-line-argument -Wno-implicit-int-float-conversion -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-psabi -c ../../libchrome/base/test/scoped_feature_list.cc -o obj/libchrome/base/test/libbase-base_test_support.scoped_feature_list.o
In file included from ../../libchrome/base/test/scoped_feature_list.cc:5:
../../libchrome/base/test/scoped_feature_list.h:26:46: error: expected ')'
  FeatureRefAndParams(const Feature& feature ABSL_ATTRIBUTE_LIFETIME_BOUND,
                                             ^
../../libchrome/base/test/scoped_feature_list.h:26:22: note: to match this '('
  FeatureRefAndParams(const Feature& feature ABSL_ATTRIBUTE_LIFETIME_BOUND,
                     ^
../../libchrome/base/test/scoped_feature_list.h:44:37: error: expected ')'
  FeatureRef(const Feature& feature ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                    ^
../../libchrome/base/test/scoped_feature_list.h:44:13: note: to match this '('
  FeatureRef(const Feature& feature ABSL_ATTRIBUTE_LIFETIME_BOUND)
            ^
In file included from ../../libchrome/base/test/scoped_feature_list.cc:22:
In file included from ../../libchrome/base/test/task_environment.h:14:
In file included from ../../libchrome/base/task/lazy_thread_pool_task_runner.h:12:
In file included from ../../libchrome/base/functional/callback.h:21:
../../libchrome/base/functional/function_ref.h:81:38: error: expected ')'
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                     ^
../../libchrome/base/functional/function_ref.h:81:14: note: to match this '('
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
             ^
../../libchrome/base/test/scoped_feature_list.cc:290:22: error: out-of-line definition of 'FeatureRefAndParams' does not match any declaration in 'base::test::FeatureRefAndParams'
FeatureRefAndParams::FeatureRefAndParams(const Feature& feature,
                     ^~~~~~~~~~~~~~~~~~~
../../libchrome/base/test/scoped_feature_list.cc:483:33: error: no matching constructor for initialization of 'const std::vector<FeatureRefAndParams> &'
  InitWithFeaturesAndParameters({{feature, feature_parameters}}, {});
                                ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:537:7: note: candidate constructor not viable: cannot convert initializer list argument to 'const std::vector<base::test::FeatureRefAndParams>::allocator_type' (aka 'const std::allocator<base::test::FeatureRefAndParams>')
      vector(const allocator_type& __a) _GLIBCXX_NOEXCEPT
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:551:7: note: candidate constructor not viable: cannot convert initializer list argument to 'std::vector::size_type' (aka 'unsigned long')
      vector(size_type __n, const allocator_type& __a = allocator_type())
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:596:7: note: candidate constructor not viable: cannot convert initializer list argument to 'const std::vector<base::test::FeatureRefAndParams>'
      vector(const vector& __x)
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:615:7: note: candidate constructor not viable: cannot convert initializer list argument to 'std::vector<base::test::FeatureRefAndParams>'
      vector(vector&&) noexcept = default;
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:673:7: note: candidate constructor not viable: no known conversion from 'const base::FieldTrialParams' (aka 'const map<basic_string<char>, basic_string<char>>') to 'base::test::FeatureRefAndParams' for 1st argument
      vector(initializer_list<value_type> __l,
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:526:7: note: candidate constructor not viable: requires 0 arguments, but 1 was provided
      vector() = default;
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:619:7: note: candidate constructor not viable: requires 2 arguments, but 1 was provided
      vector(const vector& __x, const __type_identity_t<allocator_type>& __a)
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:654:7: note: candidate constructor not viable: requires 2 arguments, but 1 was provided
      vector(vector&& __rv, const __type_identity_t<allocator_type>& __m)
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:564:7: note: candidate constructor not viable: requires at least 2 arguments, but 1 was provided
      vector(size_type __n, const value_type& __value,
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:630:7: note: candidate constructor not viable: requires 3 arguments, but 1 was provided
      vector(vector&& __rv, const allocator_type& __m, true_type) noexcept
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:635:7: note: candidate constructor not viable: requires 3 arguments, but 1 was provided
      vector(vector&& __rv, const allocator_type& __m, false_type)
      ^
/usr/bin/../lib/gcc/x86_64-linux-gnu/12/../../../../include/c++/12/bits/stl_vector.h:702:2: note: candidate constructor template not viable: requires at least 2 arguments, but 1 was provided
        vector(_InputIterator __first, _InputIterator __last,
        ^
../../libchrome/base/test/scoped_feature_list.h:159:47: note: passing argument to parameter 'enabled_features' here
      const std::vector<FeatureRefAndParams>& enabled_features,
                                              ^
5 errors generated.
[66/450] CXX obj/libchrome/base/test/libbase-base_test_support.test_simple_task_runner.o
FAILED: obj/libchrome/base/test/libbase-base_test_support.test_simple_task_runner.o
clang++ -MMD -MF obj/libchrome/base/test/libbase-base_test_support.test_simple_task_runner.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOS_CHROMEOS -DUSE_NSS_CERTS -DUSE_SYSTEM_LIBEVENT -DNO_TCMALLOC -DMOJO_BACKWARDS_COMPAT -DMOJO_CORE_LEGACY_PROTOCOL -Igen/include -I../.. -I/usr/include -I../../libchrome -Igen/libchrome -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wimplicit-int-float-conversion -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough --sysroot= -fPIE -Wno-deprecated-register -Wno-narrowing -Wno-unreachable-code-return -Wno-unused-local-typedefs -Wno-char-subscripts -std=gnu++17 -DNDEBUG -I/usr/src/googletest/googletest/include -I/usr/src/googletest/googlemock/include -Wno-unknown-warning-option -Wno-unused-command-line-argument -Wno-implicit-int-float-conversion -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-psabi -c ../../libchrome/base/test/test_simple_task_runner.cc -o obj/libchrome/base/test/libbase-base_test_support.test_simple_task_runner.o
In file included from ../../libchrome/base/test/test_simple_task_runner.cc:5:
In file included from ../../libchrome/base/test/test_simple_task_runner.h:10:
In file included from ../../libchrome/base/functional/callback.h:21:
../../libchrome/base/functional/function_ref.h:81:38: error: expected ')'
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                     ^
../../libchrome/base/functional/function_ref.h:81:14: note: to match this '('
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
             ^
1 error generated.
[67/450] CXX obj/libchrome/base/test/libbase-base_test_support.test_pending_task.o
FAILED: obj/libchrome/base/test/libbase-base_test_support.test_pending_task.o
clang++ -MMD -MF obj/libchrome/base/test/libbase-base_test_support.test_pending_task.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOS_CHROMEOS -DUSE_NSS_CERTS -DUSE_SYSTEM_LIBEVENT -DNO_TCMALLOC -DMOJO_BACKWARDS_COMPAT -DMOJO_CORE_LEGACY_PROTOCOL -Igen/include -I../.. -I/usr/include -I../../libchrome -Igen/libchrome -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wimplicit-int-float-conversion -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough --sysroot= -fPIE -Wno-deprecated-register -Wno-narrowing -Wno-unreachable-code-return -Wno-unused-local-typedefs -Wno-char-subscripts -std=gnu++17 -DNDEBUG -I/usr/src/googletest/googletest/include -I/usr/src/googletest/googlemock/include -Wno-unknown-warning-option -Wno-unused-command-line-argument -Wno-implicit-int-float-conversion -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-psabi -c ../../libchrome/base/test/test_pending_task.cc -o obj/libchrome/base/test/libbase-base_test_support.test_pending_task.o
In file included from ../../libchrome/base/test/test_pending_task.cc:5:
In file included from ../../libchrome/base/test/test_pending_task.h:10:
In file included from ../../libchrome/base/functional/callback.h:21:
../../libchrome/base/functional/function_ref.h:81:38: error: expected ')'
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                     ^
../../libchrome/base/functional/function_ref.h:81:14: note: to match this '('
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
             ^
1 error generated.
[68/450] CXX obj/libchrome/base/test/libbase-base_test_support.task_environment.o
FAILED: obj/libchrome/base/test/libbase-base_test_support.task_environment.o
clang++ -MMD -MF obj/libchrome/base/test/libbase-base_test_support.task_environment.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DOS_CHROMEOS -DUSE_NSS_CERTS -DUSE_SYSTEM_LIBEVENT -DNO_TCMALLOC -DMOJO_BACKWARDS_COMPAT -DMOJO_CORE_LEGACY_PROTOCOL -Igen/include -I../.. -I/usr/include -I../../libchrome -Igen/libchrome -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wimplicit-int-float-conversion -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough --sysroot= -fPIE -Wno-deprecated-register -Wno-narrowing -Wno-unreachable-code-return -Wno-unused-local-typedefs -Wno-char-subscripts -std=gnu++17 -DNDEBUG -I/usr/src/googletest/googletest/include -I/usr/src/googletest/googlemock/include -Wno-unknown-warning-option -Wno-unused-command-line-argument -Wno-implicit-int-float-conversion -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -Wno-psabi -c ../../libchrome/base/test/task_environment.cc -o obj/libchrome/base/test/libbase-base_test_support.task_environment.o
In file included from ../../libchrome/base/test/task_environment.cc:5:
In file included from ../../libchrome/base/test/task_environment.h:14:
In file included from ../../libchrome/base/task/lazy_thread_pool_task_runner.h:12:
In file included from ../../libchrome/base/functional/callback.h:21:
../../libchrome/base/functional/function_ref.h:81:38: error: expected ')'
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
                                     ^
../../libchrome/base/functional/function_ref.h:81:14: note: to match this '('
  FunctionRef(const Functor& functor ABSL_ATTRIBUTE_LIFETIME_BOUND)
             ^
1 error generated.
ninja: build stopped: subcommand failed.
make[1]: *** [debian/rules:29: override_dh_auto_build-arch] Error 1
make[1]: Leaving directory '/tmp/tmp.RoMyEQTYQk/libchrome-1094370'
make: *** [debian/rules:25: build] Error 2
dpkg-buildpackage: error: debian/rules build subprocess returned exit status 2

```

to do the stuff, I think I need to do the thing...

To solve this, I had to first compile libabsl-dev from source, then install it using sudo make install and then after that I ran oof@oof-h8-1440eo:/tmp/tmp.RoMyEQTYQk$ dpkg-buildpackage -d --no-sign    in the temporary build directory and tada!!! Now there is a .deb file that I can easily install...

Then the next hurdle was to do this here:


```


ninja: Entering directory `/home/oof/.floss/output/out/Default'
[1/723] ACTION //bt/flags:bluetooth_flags_c_lib_cache(//common-mk/toolchain:toolchain)
FAILED: gen/bt/flags/bluetooth_flags_c_lib_cache
/usr/bin/env ../../../staging/common-mk/file_generator_wrapper.py aconfig create-cache --package=com.android.bluetooth.flags --cache=/home/oof/.floss/output/out/Default/gen/bt/flags/bluetooth_flags_c_lib_cache --declarations=/home/oof/.floss/staging/bt/flags/a2dp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/active_device_manager.aconfig --declarations=/home/oof/.floss/staging/bt/flags/adapter.aconfig --declarations=/home/oof/.floss/staging/bt/flags/avrcp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/avrcp_controller.aconfig --declarations=/home/oof/.floss/staging/bt/flags/bta_dm.aconfig --declarations=/home/oof/.floss/staging/bt/flags/btif_dm.aconfig --declarations=/home/oof/.floss/staging/bt/flags/btm_ble.aconfig --declarations=/home/oof/.floss/staging/bt/flags/connectivity.aconfig --declarations=/home/oof/.floss/staging/bt/flags/dis.aconfig --declarations=/home/oof/.floss/staging/bt/flags/framework.aconfig --declarations=/home/oof/.floss/staging/bt/flags/gap.aconfig --declarations=/home/oof/.floss/staging/bt/flags/gatt.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hal.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hap.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hci.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hfp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hfpclient.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hid.aconfig --declarations=/home/oof/.floss/staging/bt/flags/l2cap.aconfig --declarations=/home/oof/.floss/staging/bt/flags/le_advertising.aconfig --declarations=/home/oof/.floss/staging/bt/flags/le_scanning.aconfig --declarations=/home/oof/.floss/staging/bt/flags/leaudio.aconfig --declarations=/home/oof/.floss/staging/bt/flags/mapclient.aconfig --declarations=/home/oof/.floss/staging/bt/flags/mcp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/metric.aconfig --declarations=/home/oof/.floss/staging/bt/flags/opp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/pairing.aconfig --declarations=/home/oof/.floss/staging/bt/flags/pbapclient.aconfig --declarations=/home/oof/.floss/staging/bt/flags/ranging.aconfig --declarations=/home/oof/.floss/staging/bt/flags/rfcomm.aconfig --declarations=/home/oof/.floss/staging/bt/flags/rnr.aconfig --declarations=/home/oof/.floss/staging/bt/flags/sco.aconfig --declarations=/home/oof/.floss/staging/bt/flags/sdp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/security.aconfig --declarations=/home/oof/.floss/staging/bt/flags/service_discovery.aconfig --declarations=/home/oof/.floss/staging/bt/flags/sockets.aconfig --declarations=/home/oof/.floss/staging/bt/flags/system_service.aconfig --declarations=/home/oof/.floss/staging/bt/flags/vcp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/vsc.aconfig
Traceback (most recent call last):
  File "/home/oof/.floss/output/out/Default/../../../staging/common-mk/file_generator_wrapper.py", line 19, in <module>
    subprocess.check_call(sys.argv[1:])
  File "/usr/lib/python3.10/subprocess.py", line 364, in check_call
    retcode = call(*popenargs, **kwargs)
  File "/usr/lib/python3.10/subprocess.py", line 345, in call
    with Popen(*popenargs, **kwargs) as p:
  File "/usr/lib/python3.10/subprocess.py", line 971, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.10/subprocess.py", line 1863, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'aconfig'
[2/723] ACTION //bt/sysprop:libcom.android.sysprop.bluetooth_sources(//common-mk/toolchain:toolchain)
FAILED: gen/bt/sysprop/include/a2dp.sysprop.h gen/bt/sysprop/src/a2dp.sysprop.cpp gen/bt/sysprop/public/a2dp.sysprop.h
/usr/bin/env ../../../staging/common-mk/file_generator_wrapper.py sysprop_cpp --header-dir=gen/bt/sysprop/include --public-header-dir=gen/bt/sysprop/public --source-dir=gen/bt/sysprop/src --include-name=a2dp.sysprop.h ../../../staging/bt/sysprop/a2dp.sysprop
Traceback (most recent call last):
  File "/home/oof/.floss/output/out/Default/../../../staging/common-mk/file_generator_wrapper.py", line 19, in <module>
    subprocess.check_call(sys.argv[1:])
  File "/usr/lib/python3.10/subprocess.py", line 364, in check_call
    retcode = call(*popenargs, **kwargs)
  File "/usr/lib/python3.10/subprocess.py", line 345, in call
    with Popen(*popenargs, **kwargs) as p:
  File "/usr/lib/python3.10/subprocess.py", line 971, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.10/subprocess.py", line 1863, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'sysprop_cpp'
[3/723] ACTION //bt/sysprop:libcom.android.sysprop.bluetooth_sources(//common-mk/toolchain:toolchain)
FAILED: gen/bt/sysprop/include/bta.sysprop.h gen/bt/sysprop/src/bta.sysprop.cpp gen/bt/sysprop/public/bta.sysprop.h
/usr/bin/env ../../../staging/common-mk/file_generator_wrapper.py sysprop_cpp --header-dir=gen/bt/sysprop/include --public-header-dir=gen/bt/sysprop/public --source-dir=gen/bt/sysprop/src --include-name=bta.sysprop.h ../../../staging/bt/sysprop/bta.sysprop
Traceback (most recent call last):
  File "/home/oof/.floss/output/out/Default/../../../staging/common-mk/file_generator_wrapper.py", line 19, in <module>
    subprocess.check_call(sys.argv[1:])
  File "/usr/lib/python3.10/subprocess.py", line 364, in check_call
    retcode = call(*popenargs, **kwargs)
  File "/usr/lib/python3.10/subprocess.py", line 345, in call
    with Popen(*popenargs, **kwargs) as p:
  File "/usr/lib/python3.10/subprocess.py", line 971, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.10/subprocess.py", line 1863, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'sysprop_cpp'
[4/723] ACTION //bt/sysprop:libcom.android.sysprop.bluetooth_sources(//common-mk/toolchain:toolchain)
FAILED: gen/bt/sysprop/include/ble.sysprop.h gen/bt/sysprop/src/ble.sysprop.cpp gen/bt/sysprop/public/ble.sysprop.h
/usr/bin/env ../../../staging/common-mk/file_generator_wrapper.py sysprop_cpp --header-dir=gen/bt/sysprop/include --public-header-dir=gen/bt/sysprop/public --source-dir=gen/bt/sysprop/src --include-name=ble.sysprop.h ../../../staging/bt/sysprop/ble.sysprop
Traceback (most recent call last):
  File "/home/oof/.floss/output/out/Default/../../../staging/common-mk/file_generator_wrapper.py", line 19, in <module>
    subprocess.check_call(sys.argv[1:])
  File "/usr/lib/python3.10/subprocess.py", line 364, in check_call
    retcode = call(*popenargs, **kwargs)
  File "/usr/lib/python3.10/subprocess.py", line 345, in call
    with Popen(*popenargs, **kwargs) as p:
  File "/usr/lib/python3.10/subprocess.py", line 971, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.10/subprocess.py", line 1863, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'sysprop_cpp'
[5/723] ACTION //bt/sysprop:libcom.android.sysprop.bluetooth_sources(//common-mk/toolchain:toolchain)
FAILED: gen/bt/sysprop/include/avrcp.sysprop.h gen/bt/sysprop/src/avrcp.sysprop.cpp gen/bt/sysprop/public/avrcp.sysprop.h
/usr/bin/env ../../../staging/common-mk/file_generator_wrapper.py sysprop_cpp --header-dir=gen/bt/sysprop/include --public-header-dir=gen/bt/sysprop/public --source-dir=gen/bt/sysprop/src --include-name=avrcp.sysprop.h ../../../staging/bt/sysprop/avrcp.sysprop
Traceback (most recent call last):
  File "/home/oof/.floss/output/out/Default/../../../staging/common-mk/file_generator_wrapper.py", line 19, in <module>
    subprocess.check_call(sys.argv[1:])
  File "/usr/lib/python3.10/subprocess.py", line 364, in check_call
    retcode = call(*popenargs, **kwargs)
  File "/usr/lib/python3.10/subprocess.py", line 345, in call
    with Popen(*popenargs, **kwargs) as p:
  File "/usr/lib/python3.10/subprocess.py", line 971, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.10/subprocess.py", line 1863, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'sysprop_cpp'
[6/723] ACTION //bt/sysprop:libcom.android.sysprop.bluetooth_sources(//common-mk/toolchain:toolchain)
FAILED: gen/bt/sysprop/include/device_id.sysprop.h gen/bt/sysprop/src/device_id.sysprop.cpp gen/bt/sysprop/public/device_id.sysprop.h
/usr/bin/env ../../../staging/common-mk/file_generator_wrapper.py sysprop_cpp --header-dir=gen/bt/sysprop/include --public-header-dir=gen/bt/sysprop/public --source-dir=gen/bt/sysprop/src --include-name=device_id.sysprop.h ../../../staging/bt/sysprop/device_id.sysprop
Traceback (most recent call last):
  File "/home/oof/.floss/output/out/Default/../../../staging/common-mk/file_generator_wrapper.py", line 19, in <module>
    subprocess.check_call(sys.argv[1:])
  File "/usr/lib/python3.10/subprocess.py", line 364, in check_call
    retcode = call(*popenargs, **kwargs)
  File "/usr/lib/python3.10/subprocess.py", line 345, in call
    with Popen(*popenargs, **kwargs) as p:
  File "/usr/lib/python3.10/subprocess.py", line 971, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.10/subprocess.py", line 1863, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'sysprop_cpp'
[7/723] CXX obj/bt/floss/libflags/libflags.get_flags.o
[8/723] CXX obj/bt/floss/android-base/libandroid-base.properties.o
ninja: build stopped: subcommand failed.
Traceback (most recent call last):
  File "/home/oof/android-bt/Bluetooth/./build.py", line 986, in <module>
    build.build()
  File "/home/oof/android-bt/Bluetooth/./build.py", line 644, in build
    self._target_all()
  File "/home/oof/android-bt/Bluetooth/./build.py", line 608, in _target_all
    self._target_main()
  File "/home/oof/android-bt/Bluetooth/./build.py", line 484, in _target_main
    self._gn_build('all')
  File "/home/oof/android-bt/Bluetooth/./build.py", line 426, in _gn_build
    self.run_command('build', ninja_args)
  File "/home/oof/android-bt/Bluetooth/./build.py", line 321, in run_command
    raise Exception("Return code is {}".format(rc))
Exception: Return code is 1
oof@oof-h8-1440eo:~/android-bt/Bluetooth$ find . | grep sysprop_cpp
oof@oof-h8-1440eo:~/android-bt/Bluetooth$ git submodule --init
usage: git submodule [--quiet] [--cached]
   or: git submodule [--quiet] add [-b <branch>] [-f|--force] [--name <name>] [--reference <repository>] [--] <repository> [<path>]
   or: git submodule [--quiet] status [--cached] [--recursive] [--] [<path>...]
   or: git submodule [--quiet] init [--] [<path>...]
   or: git submodule [--quiet] deinit [-f|--force] (--all| [--] <path>...)
   or: git submodule [--quiet] update [--init] [--remote] [-N|--no-fetch] [-f|--force] [--checkout|--merge|--rebase] [--[no-]recommend-shallow] [--reference <repository>] [--recursive] [--[no-]single-branch] [--] [<path>...]
   or: git submodule [--quiet] set-branch (--default|--branch <branch>) [--] <path>
   or: git submodule [--quiet] set-url [--] <path> <newurl>
   or: git submodule [--quiet] summary [--cached|--files] [--summary-limit <n>] [commit] [--] [<path>...]
   or: git submodule [--quiet] foreach [--recursive] <command>
   or: git submodule [--quiet] sync [--recursive] [--] [<path>...]
   or: git submodule [--quiet] absorbgitdirs [--] [<path>...]
oof@oof-h8-1440eo:~/android-bt/Bluetooth$ git submodule init


```

so we need to do the shitfuck maybe???

This is because there actually exists a sysprop directory here:

```

oof@oof-h8-1440eo:~/android-bt/Bluetooth/system/build/dpkg$ ls -lhS
total 24K
drwxrwxr-x 3 oof oof 4,0K Dec 18 16:47 floss
drwxrwxr-x 4 oof oof 4,0K Dec 18 19:21 libchrome
drwxrwxr-x 3 oof oof 4,0K Dec 18 16:47 modp_b64
drwxrwxr-x 5 oof oof 4,0K Dec 18 17:31 outdir
drwxrwxr-x 3 oof oof 4,0K Dec 18 16:47 sysprop
-rw-rw-r-- 1 oof oof  804 Dec 18 16:47 README.txt
oof@oof-h8-1440eo:~/android-bt/Bluetooth/system/build/dpkg$


```

but the README.md didn't bother to mention it anywhere, because of course not. That would be too easy anyway...

After installing sysprop_cpp now I am getting this error here:

```

arations=/home/oof/.floss/staging/bt/flags/vcp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/vsc.aconfig
Traceback (most recent call last):
  File "/home/oof/.floss/output/out/Default/../../../staging/common-mk/file_generator_wrapper.py", line 19, in <module>
    subprocess.check_call(sys.argv[1:])
  File "/usr/lib/python3.10/subprocess.py", line 364, in check_call
    retcode = call(*popenargs, **kwargs)
  File "/usr/lib/python3.10/subprocess.py", line 345, in call
    with Popen(*popenargs, **kwargs) as p:
  File "/usr/lib/python3.10/subprocess.py", line 971, in __init__
    self._execute_child(args, executable, preexec_fn, close_fds,
  File "/usr/lib/python3.10/subprocess.py", line 1863, in _execute_child
    raise child_exception_type(errno_num, err_msg, err_filename)
FileNotFoundError: [Errno 2] No such file or directory: 'aconfig'


```

and I am also missing the format header in c++ for some odd reason too:

```

[16/719] CXX obj/bt/system/bta/aics/libaics.aics.o
FAILED: obj/bt/system/bta/aics/libaics.aics.o
clang++ -MMD -MF obj/bt/system/bta/aics/libaics.aics.o.d -D_LARGEFILE_SOURCE -D_LARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64 -DTARGET_FLOSS -DEXPORT_SYMBOL=__attribute__\(\(visibility\(\"default\"\)\)\) -DFALLTHROUGH_INTENDED=\[\[clang::fallthrough\]\] -DEXCLUDE_NONSTANDARD_CODECS -Igen/include -I../../../staging -I/usr/include -I../../../staging/bt/system/bta/aics/include -I../../../staging/bt/system -I../../../staging/bt/flags/exported_include -I../../../staging/bt/sysprop/exported_include -I../../../staging/bt/system/linux_include -I../../../staging/bt/system/include -I../../../staging/bt/system/gd -I../../../staging/bt/system/pdl/hci/include -Igen/bt/system/gd -Igen/bt/system/gd/dumpsys/bundler -I../../../staging/bt/system/log/include -Wall -Wunused -Wbool-operation -Wfree-nonheap-object -Wint-in-bool-context -Wstring-compare -Wstring-plus-int -Wxor-used-as-pow -Wdeprecated-declarations -Wno-c99-designator -Wno-unused-parameter -Wunreachable-code -Wunreachable-code-return -ggdb3 -fstack-protector-strong -Wformat=2 -fvisibility=internal -Wa,--noexecstack -Wimplicit-fallthrough -Werror -Wno-error=deprecated-enum-enum-conversion -Wno-error=deprecated-this-capture --sysroot=/. -fPIE -fPIC -Wno-non-c-typedef-for-linkage -Wno-unreachable-code-return -Wno-defaulted-function-deleted -Wno-gnu-variable-sized-type-not-at-end -Wno-format-nonliteral -Wno-inconsistent-missing-override -Wno-unreachable-code -Wno-range-loop-construct -Wno-reorder-init-list -Wno-unused-function -Wno-unused-result -Wno-unused-variable -Wno-unused-const-variable -Wno-format -Wno-pessimizing-move -Wno-unknown-warning-option -Wno-final-dtor-non-final-class -ffile-prefix-map=../../../staging/bt/system/=\  -Wno-unused-local-typedefs -DBASE_VER=1094370 -pthread -I/usr/include/glib-2.0 -I/usr/lib/x86_64-linux-gnu/glib-2.0/include -I/usr/include/nss -I/usr/include/nspr -I/usr/include/dbus-1.0 -I/usr/lib/x86_64-linux-gnu/dbus-1.0/include -I/usr/include/libchrome -std=gnu++20 -DNDEBUG -I/usr/include/ -fno-exceptions -fno-unwind-tables -fno-asynchronous-unwind-tables -std=c++20 -c ../../../staging/bt/system/bta/aics/aics.cc -o obj/bt/system/bta/aics/libaics.aics.o
In file included from ../../../staging/bt/system/bta/aics/aics.cc:16:
../../../staging/bt/system/log/include/bluetooth/log.h:20:10: fatal error: 'format' file not found
#include <format>
         ^~~~~~~~
1 error generated.


```

to get aconfig in this bullshit, I had to do this here: `repo init -u https://android.googlesource.com/platform/manifest -b main --depth=1` and then `repo sync -c prebuilts/build-tools` and now I have aconfig with me:

```
oof@oof-h8-1440eo:~/aosp-brebuilts/prebuilts/build-tools$ cd linux-x86/bin/
oof@oof-h8-1440eo:~/aosp-brebuilts/prebuilts/build-tools/linux-x86/bin$ file aconfig
aconfig: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, stripped
oof@oof-h8-1440eo:~/aosp-brebuilts/prebuilts/build-tools/linux-x86/bin$ pwd
/home/oof/aosp-brebuilts/prebuilts/build-tools/linux-x86/bin

```

Now, to fix the format header file error I ran these commands separately:

```
#!/bin/sh


# These commands are taken straight from the thing...

# Ok, so we added -stdlib=libc++ to the external_cxxflags here...

gn gen --root=/home/oof/.floss/staging '--args=platform_subdir="bt" cc="clang" cxx="clang++" ar="llvm-ar" pkg_config="pkg-config" clang_cc=true clang_cxx=true OS="linux" sysroot="/" libdir="/usr/lib" build_root="/home/oof/.floss/output" platform2_root="/home/oof/.floss/staging" libbase_ver="NOT-INSTALLED" enable_exceptions=false external_cflags=[] external_cxxflags=["-DNDEBUG","-I/usr/include/","-stdlib=libc++"] enable_werror=true use={asan=false coverage=false cros_host=false cros_debug=false floss_rootcanal=false function_elimination_experiment=false fuzzer=false lto_experiment=false msan=false profiling=false proto_force_optimize_speed=false tcmalloc=false test=true ubsan=false android=false bt_nonstandard_codecs=false clang=true}' /home/oof/.floss/output/out/Default
ninja -C /home/oof/.floss/output/out/Default -j 8 bt:tools
ninja -C /home/oof/.floss/output/out/Default -j 8 bt:all



```





but now I am getting this kind of output here:

```
:allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x4ad8): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x4b8f): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x4bf3): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x4d17): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0x4e19): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x4ee9): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x4f12): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x4f88): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5406): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0x5557): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x55c7): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x562e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5693): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5755): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x57ba): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x580b): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x5895): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x58a1): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x58ad): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5912): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5980): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x59f0): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x5a55): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x5aa6): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x5b30): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5b3c): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5b48): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5bad): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5c1b): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5c8b): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x5cf0): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x5d41): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x5d81): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5d8d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5d99): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5dfe): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x5e6c): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x615d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x617c): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x61f2): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x66f9): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0x677e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x680e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x6a73): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0x6d11): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x6da1): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x6e12): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x7253): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x7376): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x73bb): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x7442): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x74b3): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x771c): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0x77a1): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x7831): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x7a96): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0x7c49): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x7cd9): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x7d4a): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x7ffe): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0x8081): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0x8243): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x8366): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x83ab): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x8432): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x84a3): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x93e4): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x940a): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x96b7): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x97e3): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x9809): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x9a63): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x9d3d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x9e92): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0x9ed3): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0x9efa): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xa03e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xa09e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xa15e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xa5f8): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xaa3d): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(void const*)'
/usr/bin/ld: language_y.cc:(.text+0xaaa4): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xac1a): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xae8c): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xaefa): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xb2c6): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xb334): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xb44d): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xb4cd): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xb5c7): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xb62c): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xb85c): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xb905): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xb96a): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xba9a): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xbb56): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xbbff): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xbc64): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xbe7e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xbf78): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xbfdd): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xc15e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xc2d3): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xc38f): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xc489): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xc4ee): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xc5a0): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xc607): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xc9a1): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xc9c8): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xcb38): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xcbb7): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xcc67): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xcdef): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xce5d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xcf0c): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xd12f): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xd1a0): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xd2b8): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xd2c4): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xd329): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xd445): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xd520): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xd5c2): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xd679): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xd685): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xd6ea): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xd75b): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xd877): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xd8e1): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xd952): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xdaa4): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xdb09): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xdd0a): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xdde3): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xddef): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xdf1f): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xdf90): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xe1fb): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xe25d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xe315): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xe321): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xe451): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xe4c2): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xe533): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xe6b9): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(unsigned long)'
/usr/bin/ld: language_y.cc:(.text+0xe79e): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: language_y.cc:(.text+0xe8b1): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xe9e1): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: language_y.cc:(.text+0xea52): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::basic_ostream<char, std::__1::char_traits<char> >& yy::operator<< <char>(std::__1::basic_ostream<char, std::__1::char_traits<char> >&, yy::location const&)':
language_y.cc:(.text._ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE[_ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE]+0xa6): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(void const*)'
/usr/bin/ld: language_y.cc:(.text._ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE[_ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE]+0xc2): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(int)'
/usr/bin/ld: language_y.cc:(.text._ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE[_ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE]+0xda): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(int)'
/usr/bin/ld: language_y.cc:(.text._ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE[_ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE]+0x110): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(int)'
/usr/bin/ld: language_y.cc:(.text._ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE[_ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE]+0x128): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(int)'
/usr/bin/ld: language_y.cc:(.text._ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE[_ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8locationE]+0x156): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(int)'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::variant<long, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, std::__1::variant<long, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > >, (void*)0>(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, std::__1::variant<long, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > >&&)':
language_y.cc:(.text._ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_7variantIJlS6_EEEEC2IRS6_S8_LPv0EEEOT_OT0_[_ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_7variantIJlS6_EEEEC2IRS6_S8_LPv0EEEOT_OT0_]+0x2d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, TypeDef*>::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, TypeDef*&, (void*)0>(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, TypeDef*&)':
language_y.cc:(.text._ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEP7TypeDefEC2IRS6_RS8_LPv0EEEOT_OT0_[_ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEP7TypeDefEC2IRS6_RS8_LPv0EEEOT_OT0_]+0x2d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, PacketDef*>::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, PacketDef*&, (void*)0>(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, PacketDef*&)':
language_y.cc:(.text._ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEP9PacketDefEC2IRS6_RS8_LPv0EEEOT_OT0_[_ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEP9PacketDefEC2IRS6_RS8_LPv0EEEOT_OT0_]+0x2d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, FieldList*>::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, FieldList*&, (void*)0>(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&, FieldList*&)':
language_y.cc:(.text._ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEP9FieldListEC2IRS6_RS8_LPv0EEEOT_OT0_[_ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEP9FieldListEC2IRS6_RS8_LPv0EEEOT_OT0_]+0x2d): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, FieldList*>::~pair()':
language_y.cc:(.text._ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEP9FieldListED2Ev[_ZNSt3__14pairINS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEP9FieldListED2Ev]+0x11): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::~basic_string()'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const, std::__1::variant<long, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >::pair<std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::variant<long, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >&, (void*)0>(std::__1::pair<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >, std::__1::variant<long, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > > >&)':
language_y.cc:(.text._ZNSt3__14pairIKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_7variantIJlS6_EEEEC2IRNS0_IS6_S9_EELPv0EEEOT_[_ZNSt3__14pairIKNS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEENS_7variantIJlS6_EEEEC2IRNS0_IS6_S9_EELPv0EEEOT_]+0x31): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::__variant_detail::__alt<1ul, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > >::__alt<std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&>(std::__1::in_place_t, std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >&)':
language_y.cc:(.text._ZNSt3__116__variant_detail5__altILm1ENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEC2IJRS7_EEENS_10in_place_tEDpOT_[_ZNSt3__116__variant_detail5__altILm1ENS_12basic_stringIcNS_11char_traitsIcEENS_9allocatorIcEEEEEC2IJRS7_EEENS_10in_place_tEDpOT_]+0x29): undefined reference to `std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> >::basic_string(std::__1::basic_string<char, std::__1::char_traits<char>, std::__1::allocator<char> > const&)'
/usr/bin/ld: obj/gen/bt/system/gd/packet/parser/pktparser.language_y.o: in function `std::__1::basic_ostream<char, std::__1::char_traits<char> >& yy::operator<< <char>(std::__1::basic_ostream<char, std::__1::char_traits<char> >&, yy::position const&)':
language_y.cc:(.text._ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8positionE[_ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8positionE]+0x47): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(int)'
/usr/bin/ld: language_y.cc:(.text._ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8positionE[_ZN2yylsIcEERNSt3__113basic_ostreamIT_NS1_11char_traitsIS3_EEEES7_RKNS_8positionE]+0x63): undefined reference to `std::__1::basic_ostream<char, std::__1::char_traits<char> >::operator<<(int)'
clang: error: linker command failed with exit code 1 (use -v to see invocation)
ninja: build stopped: subcommand failed.
ninja: Entering directory `/home/oof/.floss/output/out/Default'
[1/709] ACTION //bt/flags:bluetooth_flags_c_lib_cache(//common-mk/toolchain:toolchain)
FAILED: gen/bt/flags/bluetooth_flags_c_lib_cache
/usr/bin/env ../../../staging/common-mk/file_generator_wrapper.py aconfig create-cache --package=com.android.bluetooth.flags --cache=/home/oof/.floss/output/out/Default/gen/bt/flags/bluetooth_flags_c_lib_cache --declarations=/home/oof/.floss/staging/bt/flags/a2dp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/active_device_manager.aconfig --declarations=/home/oof/.floss/staging/bt/flags/adapter.aconfig --declarations=/home/oof/.floss/staging/bt/flags/avrcp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/avrcp_controller.aconfig --declarations=/home/oof/.floss/staging/bt/flags/bta_dm.aconfig --declarations=/home/oof/.floss/staging/bt/flags/btif_dm.aconfig --declarations=/home/oof/.floss/staging/bt/flags/btm_ble.aconfig --declarations=/home/oof/.floss/staging/bt/flags/connectivity.aconfig --declarations=/home/oof/.floss/staging/bt/flags/dis.aconfig --declarations=/home/oof/.floss/staging/bt/flags/framework.aconfig --declarations=/home/oof/.floss/staging/bt/flags/gap.aconfig --declarations=/home/oof/.floss/staging/bt/flags/gatt.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hal.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hap.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hci.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hfp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hfpclient.aconfig --declarations=/home/oof/.floss/staging/bt/flags/hid.aconfig --declarations=/home/oof/.floss/staging/bt/flags/l2cap.aconfig --declarations=/home/oof/.floss/staging/bt/flags/le_advertising.aconfig --declarations=/home/oof/.floss/staging/bt/flags/le_scanning.aconfig --declarations=/home/oof/.floss/staging/bt/flags/leaudio.aconfig --declarations=/home/oof/.floss/staging/bt/flags/mapclient.aconfig --declarations=/home/oof/.floss/staging/bt/flags/mcp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/metric.aconfig --declarations=/home/oof/.floss/staging/bt/flags/opp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/pairing.aconfig --declarations=/home/oof/.floss/staging/bt/flags/pbapclient.aconfig --declarations=/home/oof/.floss/staging/bt/flags/ranging.aconfig --declarations=/home/oof/.floss/staging/bt/flags/rfcomm.aconfig --declarations=/home/oof/.floss/staging/bt/flags/rnr.aconfig --declarations=/home/oof/.floss/staging/bt/flags/sco.aconfig --declarations=/home/oof/.floss/staging/bt/flags/sdp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/security.aconfig --declarations=/home/oof/.floss/staging/bt/flags/service_discovery.aconfig --declarations=/home/oof/.floss/staging/bt/flags/sockets.aconfig --declarations=/home/oof/.floss/staging/bt/flags/system_service.aconfig --declarations=/home/oof/.floss/staging/bt/flags/vcp.aconfig --declarations=/home/oof/.floss/staging/bt/flags/vsc.aconfig
error: the following required arguments were not provided:
  --container <container>

Usage: aconfig create-cache --package <package> --container <container> --cache <cache> --declarations <declarations>

For more information, try '--help'.
Traceback (most recent call last):
  File "/home/oof/.floss/output/out/Default/../../../staging/common-mk/file_generator_wrapper.py", line 19, in <module>
    subprocess.check_call(sys.argv[1:])
  File "/usr/lib/python3.10/subprocess.py", line 369, in check_call
    raise CalledProcessError(retcode, cmd)
subprocess.CalledProcessError: Command '['aconfig', 'create-cache', '--package=com.android.bluetooth.flags', '--cache=/home/oof/.floss/output/out/Default/gen/bt/flags/bluetooth_flags_c_lib_cache', '--declarations=/home/oof/.floss/staging/bt/flags/a2dp.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/active_device_manager.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/adapter.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/avrcp.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/avrcp_controller.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/bta_dm.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/btif_dm.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/btm_ble.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/connectivity.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/dis.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/framework.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/gap.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/gatt.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/hal.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/hap.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/hci.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/hfp.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/hfpclient.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/hid.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/l2cap.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/le_advertising.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/le_scanning.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/leaudio.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/mapclient.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/mcp.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/metric.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/opp.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/pairing.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/pbapclient.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/ranging.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/rfcomm.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/rnr.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/sco.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/sdp.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/security.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/service_discovery.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/sockets.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/system_service.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/vcp.aconfig', '--declarations=/home/oof/.floss/staging/bt/flags/vsc.aconfig']' returned non-zero exit status 2.
[8/709] CXX obj/gen/bt/sysprop/src/libcom.android.sysprop.bluetooth.device_id.sysprop.o
ninja: build stopped: subcommand failed.
oof@oof-h8-1440eo:~/android-bt/Bluetooth$

```

so there is still something getting messed up with the aconfig stuff, but there is also a lot of linker errors probably related to the c++ stuff

In addition, I also had to do this kind of bullshit here and get a slightly older thing:

```
oof@oof-h8-1440eo:~/thing-prebuilts/prebuilts/build-tools/linux-x86/bin$ repo init -u https://android.googlesource.com/platform/manifest -b android-15.0.0_r1 --depth=1

```

Also there was this error here:

```



```


which was solved by simply using this here:

```
oof@oof-h8-1440eo:~/thing-prebuilts$ repo sync -c prebuilts/clang/host/linux-x86
```

How should I actually compile the fuzzer?

Well, maybe this here: https://source.android.com/docs/automotive/tools/fuzz would be of use maybe??? I don't really know for certain though...

The correct version of the prebuilts are in ~/thing-prebuilts

And for the clang I just added this path here to my PATH environment variable:

```
oof@oof-h8-1440eo:~/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin$ pwd
/home/oof/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin
oof@oof-h8-1440eo:~/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin$
```

now, one final compile error which I got was this here:

```
In file included from /usr/include/libchrome/base/containers/span.h:18:
/usr/include/libchrome/base/containers/checked_iterators.h:248:8: error: no template named '__is_cpp17_contiguous_iterator'; did you mean '__libcpp_is_contiguous_iterator'?
  248 | struct __is_cpp17_contiguous_iterator<::base::CheckedContiguousIterator<T>>
      |        ^~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
      |        __libcpp_is_contiguous_iterator
/home/oof/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin/../include/c++/v1/__iterator/iterator_traits.h:452:8: note: '__libcpp_is_contiguous_iterator' declared here
  452 | struct __libcpp_is_contiguous_iterator
      |        ^
1 error generated.
[34/660] CXX obj/bt/system/gd/packet/BluetoothPacketSources.raw_builder.o
ninja: build stopped: subcommand failed.
oof@oof-h8-1440eo:~/android-bt/Bluetooth$


```

so let's just replace that with the other thing maybe???

That seemed to have worked. Now I am getting this bullshit here:

```
deprecated-pragma]
   57 |     {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, 0, InitDefaultsscc_info_AacEncoderParam_mmc_5fconfig_2eproto}, {}};
      |       ^
/home/oof/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin/../include/c++/v1/__atomic/atomic_init.h:24:43: note: macro marked 'deprecated' here
   24 | #  pragma clang deprecated(ATOMIC_VAR_INIT)
      |                                           ^
gen/include/mmc/proto/mmc_config.pb.cc:71:7: error: macro 'ATOMIC_VAR_INIT' has been marked as deprecated [-Werror,-Wdeprecated-pragma]
   71 |     {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 4, 0, InitDefaultsscc_info_ConfigParam_mmc_5fconfig_2eproto}, {
      |       ^
/home/oof/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin/../include/c++/v1/__atomic/atomic_init.h:24:43: note: macro marked 'deprecated' here
   24 | #  pragma clang deprecated(ATOMIC_VAR_INIT)
      |                                           ^
gen/include/mmc/proto/mmc_config.pb.cc:89:7: error: macro 'ATOMIC_VAR_INIT' has been marked as deprecated [-Werror,-Wdeprecated-pragma]
   89 |     {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, 0, InitDefaultsscc_info_Lc3Param_mmc_5fconfig_2eproto}, {}};
      |       ^
/home/oof/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin/../include/c++/v1/__atomic/atomic_init.h:24:43: note: macro marked 'deprecated' here
   24 | #  pragma clang deprecated(ATOMIC_VAR_INIT)
      |                                           ^
gen/include/mmc/proto/mmc_config.pb.cc:103:7: error: macro 'ATOMIC_VAR_INIT' has been marked as deprecated [-Werror,-Wdeprecated-pragma]
  103 |     {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, 0, InitDefaultsscc_info_SbcDecoderParam_mmc_5fconfig_2eproto}, {}};
      |       ^
/home/oof/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin/../include/c++/v1/__atomic/atomic_init.h:24:43: note: macro marked 'deprecated' here
   24 | #  pragma clang deprecated(ATOMIC_VAR_INIT)
      |                                           ^
gen/include/mmc/proto/mmc_config.pb.cc:117:7: error: macro 'ATOMIC_VAR_INIT' has been marked as deprecated [-Werror,-Wdeprecated-pragma]
  117 |     {{ATOMIC_VAR_INIT(::PROTOBUF_NAMESPACE_ID::internal::SCCInfoBase::kUninitialized), 0, 0, InitDefaultsscc_info_SbcEncoderParam_mmc_5fconfig_2eproto}, {}};
      |       ^
/home/oof/thing-prebuilts/prebuilts/clang/host/linux-x86/clang-r522817/bin/../include/c++/v1/__atomic/atomic_init.h:24:43: note: macro marked 'deprecated' here
   24 | #  pragma clang deprecated(ATOMIC_VAR_INIT)
      |                                           ^
5 errors generated.
[102/633] CXX obj/bt/system/audio/asrc/libbt-audio-asrc.asrc_resampler.o
ninja: build stopped: subcommand failed.

```


sooo just add that command line bullshit to the thing???

Now my script looks something like this here:

```

#!/bin/sh


# These commands are taken straight from the thing...

# Ok, so we added -stdlib=libc++ to the external_cxxflags here... and some other flags too   ("-Wno-error=unused-command-line-argument","-Wno-error=deprecated-pragma","-stdlib=libc++")

gn gen --root=/home/oof/.floss/staging '--args=platform_subdir="bt" cc="clang" cxx="clang++" ar="llvm-ar" pkg_config="pkg-config" clang_cc=true clang_cxx=true OS="linux" sysroot="/" libdir="/usr/lib" build_root="/home/oof/.floss/output" platform2_root="/home/oof/.floss/staging" libbase_ver="NOT-INSTALLED" enable_exceptions=false external_cflags=[] external_cxxflags=["-DNDEBUG","-I/usr/include/","-Wno-error=unused-command-line-argument","-Wno-error=deprecated-pragma","-stdlib=libc++"] external_ldflags=["-lc++"] enable_werror=true use={asan=false coverage=false cros_host=false cros_debug=false floss_rootcanal=false function_elimination_experiment=false fuzzer=false lto_experiment=false msan=false profiling=false proto_force_optimize_speed=false tcmalloc=false test=true ubsan=false android=false bt_nonstandard_codecs=false clang=true}' /home/oof/.floss/output/out/Default


ninja -C /home/oof/.floss/output/out/Default -j 8 bt:tools
ninja -C /home/oof/.floss/output/out/Default -j 8 bt:all




```






