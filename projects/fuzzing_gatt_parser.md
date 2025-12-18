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





