
# Fuzzing apache httpd (again)

Ok, so I have previously fuzzed the apache httpd stuff, but it didn't yield any results, because of reasons. Now, instead I am going to try to fuzz apache httpd with libfuzzer instead of doing some janky stuff.

I am going to use the code from oss-fuzz from here: https://github.com/google/oss-fuzz/tree/master/projects/apache-httpd/ to help.

## Beginnings

Now, the start is quite easy, because you basically have to just follow the Dockerfile stuff initially.

After compiling httpd with afl-clang-fast and afl-clang-fast++ as compilers and with address sanitizer and undefined sanitizer, I inspected the fuzzer sources.


Here is the source code of the request fuzzer:

```

/* Copyright 2021 Google LLC
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
      http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
#include "apr.h"
#include "apr_file_io.h"
#include "apr_poll.h"
#include "apr_portable.h"
#include "apr_proc_mutex.h"
#include "apr_signal.h"
#include "apr_strings.h"
#include "apr_thread_mutex.h"
#include "apr_thread_proc.h"
#include "http_core.h"

#define APR_WANT_STRFUNC
#include "apr_file_io.h"
#include "apr_fnmatch.h"
#include "apr_want.h"

#include "apr_poll.h"
#include "apr_want.h"

#include "ap_config.h"
#include "ap_expr.h"
#include "ap_listen.h"
#include "ap_provider.h"
#include "ap_regex.h"

#include "http_log.h"
#include "http_protocol.h"

#include "ada_fuzz_header.h"

static const char *http_scheme2(const request_rec *r) {
  /*
   * The http module shouldn't return anything other than
   * "http" (the default) or "https".
   */
  if (r->server->server_scheme &&
      (strcmp(r->server->server_scheme, "https") == 0))
    return "https";

  return "http";
}

extern request_rec *ap_create_request(conn_rec *conn);
extern int read_request_line(request_rec *r, apr_bucket_brigade *bb);

int LLVMFuzzerInitialize(int *argc, char ***argv) {
  apr_pool_create(&apr_hook_global_pool, NULL);
  ap_open_stderr_log(apr_hook_global_pool);
  ap_hook_http_scheme(http_scheme2, NULL, NULL, APR_HOOK_REALLY_LAST);
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  af_gb_init();

  const uint8_t *data2 = data;
  size_t size2 = size;

  /* get random data for the fuzzer */
  char *new_str = af_gb_get_null_terminated(&data2, &size2);
  char *new_str2 = af_gb_get_null_terminated(&data2, &size2);
  char *new_str3 = af_gb_get_null_terminated(&data2, &size2);
  char *new_str4 = af_gb_get_null_terminated(&data2, &size2);
  char *new_str5 = af_gb_get_null_terminated(&data2, &size2);
  if (new_str != NULL &&
      new_str2 != NULL &&
      new_str3 != NULL &&
      new_str4 != NULL &&
      new_str5 != NULL) {

    /* this is the main fuzzing logic */

    apr_pool_initialize();
    apr_pool_t *v = NULL;
    apr_pool_create(&v, NULL);

    conn_rec conn;
    conn.pool = v;
    server_rec base_server;
    conn.base_server = &base_server;
    conn.bucket_alloc = apr_bucket_alloc_create(conn.pool);
    ap_method_registry_init(conn.pool);

    //server_rec server;

    /* Simulate ap_read_request */
    request_rec *r = NULL;
    r = ap_create_request(&conn);

    /* create a logs array for the request */
    struct ap_logconf logs = {};
    char *log_levels = calloc(1000, 1);
    memset(log_levels, 0, 1000);
    logs.module_levels = log_levels;
    r->log = &logs;
    if (r != NULL) {
      apr_bucket_brigade *tmp_bb = apr_brigade_create(r->pool, r->connection->bucket_alloc);
      conn.keepalive = AP_CONN_UNKNOWN;

      ap_run_pre_read_request(r, &conn);

      core_server_config conf_mod;
      conf_mod.http_conformance   = (char)af_get_short(&data2, &size2);
      conf_mod.http09_enable      = (char)af_get_short(&data2, &size2);
      conf_mod.http_methods       = (char)af_get_short(&data2, &size2);
      void **module_config_arr = malloc(1000);
      module_config_arr[0] = &conf_mod;

      r->server->module_config = module_config_arr;
      ap_set_core_module_config(r->server->module_config, &conf_mod);

      /* randomise content of request */
      r->unparsed_uri           = new_str;
      r->uri                    = new_str2;
      r->server->server_scheme  = new_str3;
      r->method                 = new_str4;
      r->the_request            = new_str5;

      /* main target */
      ap_parse_request_line(r);

      free(module_config_arr);
    }
    free(log_levels);
    apr_pool_terminate();
  }

  af_gb_cleanup();
  return 0;
}


```

but then if you look at the `r->the_request` construct, it actually is only the very first line of the request, not the request text as a whole. This means that we are only fuzzing the parsing logic, which parses the very first line of each HTTP request. To improve this situation, we should find a function which actually parses the entire request instead of just the first line.

After simply grepping for "parse" and "request", I found this in request.c :

```

/* This is the master logic for processing requests.  Do NOT duplicate
 * this logic elsewhere, or the security model will be broken by future
 * API changes.  Each phase must be individually optimized to pick up
 * redundant/duplicate calls by subrequests, and redirects.
 */
AP_DECLARE(int) ap_process_request_internal(request_rec *r)
{
    // SNIP

```

Maybe we should use ap_process_request_internal instead? Let's look at the documentation: https://nightlies.apache.org/httpd/trunk/doxygen/group__APACHE__CORE__REQ.html#ga7cf27cfba3c6dd2c9ad8685dd515923e

Oh, so that function is actually used by in turn ap_process_request . There is actually also a function called "ap_process_request_after_handler" , so how do we use that?????

There is this code in http_request.c in the http module:

```

void ap_process_async_request(request_rec *r)
{
    conn_rec *c = r->connection;
    int access_status;

    /* Give quick handlers a shot at serving the request on the fast
     * path, bypassing all of the other Apache hooks.
     *
     * This hook was added to enable serving files out of a URI keyed
     * content cache ( e.g., Mike Abbott's Quick Shortcut Cache,
     * described here: http://oss.sgi.com/projects/apache/mod_qsc.html )
     *
     * It may have other uses as well, such as routing requests directly to
     * content handlers that have the ability to grok HTTP and do their
     * own access checking, etc (e.g. servlet engines).
     *
     * Use this hook with extreme care and only if you know what you are
     * doing.
     */
    AP_PROCESS_REQUEST_ENTRY((uintptr_t)r, r->uri);
    if (ap_extended_status) {
        ap_time_process_request(r->connection->sbh, START_PREQUEST);
    }

    if (APLOGrtrace4(r)) {
        int i;
        const apr_array_header_t *t_h = apr_table_elts(r->headers_in);
        const apr_table_entry_t *t_elt = (apr_table_entry_t *)t_h->elts;
        ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r,
                      "Headers received from client:");
        for (i = 0; i < t_h->nelts; i++, t_elt++) {
            ap_log_rerror(APLOG_MARK, APLOG_TRACE4, 0, r, "  %s: %s",
                          ap_escape_logitem(r->pool, t_elt->key),
                          ap_escape_logitem(r->pool, t_elt->val));
        }
    }

#if APR_HAS_THREADS
    apr_thread_mutex_create(&r->invoke_mtx, APR_THREAD_MUTEX_DEFAULT, r->pool);
    apr_thread_mutex_lock(r->invoke_mtx);
#endif
    access_status = ap_run_quick_handler(r, 0);  /* Not a look-up request */
    if (access_status == DECLINED) {
        access_status = ap_process_request_internal(r);
        if (access_status == OK) {
            access_status = ap_invoke_handler(r);
        }
    }

    if (access_status == SUSPENDED) {
        /* TODO: Should move these steps into a generic function, so modules
         * working on a suspended request can also call _ENTRY again.
         */
        AP_PROCESS_REQUEST_RETURN((uintptr_t)r, r->uri, access_status);
        if (ap_extended_status) {
            ap_time_process_request(c->sbh, STOP_PREQUEST);
        }
        if (c->cs)
            c->cs->state = CONN_STATE_SUSPENDED;
#if APR_HAS_THREADS
        apr_thread_mutex_unlock(r->invoke_mtx);
#endif
        return;
    }
#if APR_HAS_THREADS
    apr_thread_mutex_unlock(r->invoke_mtx);
#endif

    ap_die_r(access_status, r, HTTP_OK);

    ap_process_request_after_handler(r);
}

AP_DECLARE(void) ap_process_request(request_rec *r)
{
    apr_bucket_brigade *bb;
    apr_bucket *b;
    conn_rec *c = r->connection;
    apr_status_t rv;

    ap_process_async_request(r);

    if (ap_run_input_pending(c) != OK) {
        bb = ap_acquire_brigade(c);
        b = apr_bucket_flush_create(c->bucket_alloc);
        APR_BRIGADE_INSERT_HEAD(bb, b);
        rv = ap_pass_brigade(c->output_filters, bb);
        if (APR_STATUS_IS_TIMEUP(rv)) {
            /*
             * Notice a timeout as an error message. This might be
             * valuable for detecting clients with broken network
             * connections or possible DoS attacks.
             */
            ap_log_cerror(APLOG_MARK, APLOG_INFO, rv, c, APLOGNO(01581)
                          "flushing data to the client");
        }
        ap_release_brigade(c, bb);
    }
    if (ap_extended_status) {
        ap_time_process_request(c->sbh, STOP_PREQUEST);
    }
}


```

ap_process_request seems like a promising target for fuzzing.

In http_core.c there is this code:

```

static int ap_process_http_sync_connection(conn_rec *c)
{
    request_rec *r;
    conn_state_t *cs = c->cs;
    apr_socket_t *csd = NULL;
    int mpm_state = 0;

    /*
     * Read and process each request found on our connection
     * until no requests are left or we decide to close.
     */

    ap_update_child_status_from_conn(c->sbh, SERVER_BUSY_READ, c);
    while ((r = ap_read_request(c)) != NULL) {
        apr_interval_time_t keep_alive_timeout = r->server->keep_alive_timeout;

        /* To preserve legacy behaviour, use the keepalive timeout from the
         * base server (first on this IP:port) when none is explicitly
         * configured on this server.
         */
        if (!r->server->keep_alive_timeout_set) {
            keep_alive_timeout = c->base_server->keep_alive_timeout;
        }

        if (r->status == HTTP_OK) {
            if (cs)
                cs->state = CONN_STATE_HANDLER;
            ap_update_child_status(c->sbh, SERVER_BUSY_WRITE, r);
            ap_process_request(r);
            /* After the call to ap_process_request, the
             * request pool will have been deleted.  We set
             * r=NULL here to ensure that any dereference
             * of r that might be added later in this function
             * will result in a segfault immediately instead
             * of nondeterministic failures later.
             */
            r = NULL;
        }

        if (c->keepalive != AP_CONN_KEEPALIVE || c->aborted)
            break;

        ap_update_child_status(c->sbh, SERVER_BUSY_KEEPALIVE, NULL);

        if (ap_mpm_query(AP_MPMQ_MPM_STATE, &mpm_state)) {
            break;
        }

        if (mpm_state == AP_MPMQ_STOPPING) {
          break;
        }

        if (!csd) {
            csd = ap_get_conn_socket(c);
        }
        apr_socket_opt_set(csd, APR_INCOMPLETE_READ, 1);
        apr_socket_timeout_set(csd, keep_alive_timeout);
        /* Go straight to select() to wait for the next request */
    }

    return OK;
}

```

so I think what we need to do is replicate in our wrapper what the code in `ap_read_request(c)` does. But in fuzz_request.c (the fuzzing wrapper), there is this comment: `/* Simulate ap_read_request */` so I think we do that already and we do not need to do anything. Maybe.

Also I think that we should fuzz apreq (https://httpd.apache.org/apreq/)

## Trying to craft a POC

Ok, so I think I actually found a vulnerability in a component of apache! I can't reveal it yet, because I think it is an entirely new vulnerability.

Ok, so after a bit of investigation, it looks like this vulnerability can't be reached in an easy way. Anyway.

## Trying to fuzz better

In the apache httpd oss-fuzz source code, there isn't really a good "fuzz everything" fuzzer. After a quick google search, I found this: https://animal0day.blogspot.com/2017/05/fuzzing-apache-httpd-server-with.html which seems like a nice tutorial. I actually want to do a couple of changes to the source code, because I want to try persistent fuzzing and stuff like that. Let's see how that works out.

First of all I downloaded all of the source code which we want, I am now trying to compile the libraries. I am also going to make an automated script to compile everything. I am going to edventually put it here: https://github.com/personnumber3377/httpd_fuzzing_stuff

My build script will be based on this script: https://gist.githubusercontent.com/n30m1nd/14418fd425a3b2d14b64650710fae301/raw/e1cff738eb1ffaa55cb8a1a66bb1a2b06ed7f97e/compile_httpd_with_flags.sh

I think that the best strategy is to combine the strategies from here: https://securitylab.github.com/research/fuzzing-apache-1/ and from the blogspot post.

I added this code: https://github.com/personnumber3377/httpd_fuzzing_stuff/commit/46d6597fb253fc6ae43c57659efc4a2868873be9 . I had trouble compiling the crypto module, because reasons.

## Adding the fuzzing harness.

Ok, so now I just need to add the fuzzing harness to the code.

I am using apache httpd commit a34f3346ade91b68dc1294731b13e408a582f069 .

I had some trouble getting the fuzzer to work, so I changed to the 2-4-x branch (the same version as in the blogspot post) .


If I try to run the fuzzer, I get this coredump:

```

oof@oof-h8-1440eo:~/work/better_fuzzer$ coredumpctl gdb 4480
           PID: 4480 (httpd)
           UID: 1000 (oof)
           GID: 1000 (oof)
        Signal: 4 (ILL)
     Timestamp: Sat 2024-06-15 05:57:00 EEST (1min 10s ago)
  Command Line: ./httpd -X
    Executable: /home/oof/work/better_fuzzer/httpd_install/bin/httpd
 Control Group: /user.slice/user-1000.slice/session-c1.scope
          Unit: session-c1.scope
         Slice: user-1000.slice
       Session: c1
     Owner UID: 1000 (oof)
       Boot ID: 43db86b901ca4dbfb39085d33fb0c4de
    Machine ID: 09143d0261be487380a9ec9bf41d5922
      Hostname: oof-h8-1440eo
       Storage: /var/lib/systemd/coredump/core.httpd.1000.43db86b901ca4dbfb39085d33fb0c4de.4480.1718420220000000.zst (present)
     Disk Size: 1.4M
       Message: Process 4480 (httpd) of user 1000 dumped core.

                Found module /home/oof/work/better_fuzzer/httpd_install/bin/httpd with build-id: 4dc0bc2652a4d52333e5d368fe2d74499e52aa17
                Found module /home/oof/work/better_fuzzer/httpd_install/lib/libapr-1.so.0.7.4 with build-id: d70ae86e3a1e117ccae63a6800dc887198d15219
                Found module /home/oof/work/better_fuzzer/httpd_install/lib/libaprutil-1.so.0.6.3 with build-id: b93ed931bbeb8c68871a9baba49b1385fc74f151
                Found module /home/oof/work/better_fuzzer/httpd_install/lib/libpcre.so.1.2.8 with build-id: 1e35eb515075e7cb745843e269a20b333e803bfe
                Found module /home/oof/work/better_fuzzer/httpd_install/lib/libnghttp2.so.14.28.1 with build-id: 04edc87700e114cae64c9493d8b58ff1cbd183c5
                Found module linux-vdso.so.1 with build-id: d0925f56dcc44129a9fbd6897ae9a5a5aab11f7b
                Found module ld-linux-x86-64.so.2 with build-id: 246ac0d8deba5a40c63e9a1a87d4d779d8eb589f
                Found module libc.so.6 with build-id: 962015aa9d133c6cbcfb31ec300596d7f44d3348
                Found module libgcc_s.so.1 with build-id: e3a44e0da9c6e835d293ed8fd2882b4c4a87130c
                Found module libm.so.6 with build-id: b55ba6d8b5954b479fab2a69a54b9f56451fbee0
                Found module libuuid.so.1 with build-id: 2ad45e51f4ac4fc8b5f4ef938a18ca8e0a05e4af
                Found module libexpat.so.1 with build-id: 488cca1472bb121a12e1c77bb58fe0a5c52f2aa9
                Found module libcrypto.so.3 with build-id: ca84e22a798dabf117de600cb13469a59f775d2a
                Found module libssl.so.3 with build-id: 9e2ad2d446d1e0e442154f9df9a3daf6a04bd645
                Stack trace of thread 4480:
                #0  0x00000000006446ec n/a (/home/oof/work/better_fuzzer/httpd_install/bin/httpd + 0x2446ec)

GNU gdb (Ubuntu 12.1-0ubuntu1~22.04) 12.1
Copyright (C) 2022 Free Software Foundation, Inc.
License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>
This is free software: you are free to change and redistribute it.
There is NO WARRANTY, to the extent permitted by law.
Type "show copying" and "show warranty" for details.
This GDB was configured as "x86_64-linux-gnu".
Type "show configuration" for configuration details.
For bug reporting instructions, please see:
<https://www.gnu.org/software/gdb/bugs/>.
Find the GDB manual and other documentation resources online at:
    <http://www.gnu.org/software/gdb/documentation/>.

For help, type "help".
Type "apropos word" to search for commands related to "word"...
Reading symbols from /home/oof/work/better_fuzzer/httpd_install/bin/httpd...

warning: Can't open file /dev/zero (deleted) during file-backed mapping note processing
[New LWP 4480]
[New LWP 4481]
[New LWP 4482]
[Thread debugging using libthread_db enabled]
Using host libthread_db library "/lib/x86_64-linux-gnu/libthread_db.so.1".
Core was generated by `./httpd -X'.
Program terminated with signal SIGILL, Illegal instruction.
#0  0x00000000006446ec in merge_core_dir_configs (a=a@entry=0x625000098928, basev=basev@entry=0x625000060d70,
    newv=0x6250000619d0) at core.c:391
391	            (conf->etag_add & (~ new->etag_remove)) | new->etag_add;
[Current thread is 1 (Thread 0x7fe446a18880 (LWP 4480))]
(gdb) where
#0  0x00000000006446ec in merge_core_dir_configs (a=a@entry=0x625000098928, basev=basev@entry=0x625000060d70,
    newv=0x6250000619d0) at core.c:391
#1  0x0000000000750f3d in ap_merge_per_dir_configs (p=p@entry=0x625000098928, base=base@entry=0x625000060c98,
    new_conf=0x625000061010) at config.c:301
#2  0x00000000006bd1e5 in ap_directory_walk (r=0x6250000989a0) at request.c:1054
#3  0x0000000000681e09 in core_map_to_storage (r=0x6250000989a0) at core.c:4796
#4  0x000000000069c209 in ap_run_map_to_storage (r=r@entry=0x6250000989a0) at request.c:82
#5  0x00000000006a5664 in ap_process_request_internal (r=r@entry=0x6250000989a0) at request.c:287
#6  0x00000000008dae6d in ap_process_async_request (r=<optimized out>, r@entry=0x6250000989a0) at http_request.c:450
#7  0x00000000008de71c in ap_process_request (r=0x6250000989a0) at http_request.c:487
#8  0x00000000008baba3 in ap_process_http_sync_connection (c=<optimized out>) at http_core.c:208
#9  0x00000000008b8579 in ap_process_http_connection (c=0x62500008c390) at http_core.c:249
#10 0x00000000007cfa69 in ap_run_process_connection (c=c@entry=0x62500008c390) at connection.c:42
#11 0x00000000007d339c in ap_process_connection (c=c@entry=0x62500008c390, csd=<optimized out>) at connection.c:217
#12 0x0000000000df4cc2 in child_main (child_num_arg=<optimized out>, child_bucket=<optimized out>) at prefork.c:667
#13 0x0000000000dee4c7 in make_child (s=0x625000043ec0, slot=slot@entry=0) at prefork.c:705
#14 0x0000000000de66de in prefork_run (_pconf=<optimized out>, plog=<optimized out>, s=<optimized out>)
    at prefork.c:922
#15 0x000000000054bcef in ap_run_mpm (pconf=pconf@entry=0x625000007928, plog=0x625000050128, s=0x625000043ec0)
    at mpm_common.c:95
#16 0x00000000004ec4e5 in main (argc=<optimized out>, argv=<optimized out>) at main.c:1087
(gdb)


```

## Solving the bug.

The bug was actually caused by some bullshit compile flag here: `LIBS="-L$apr/.libs -L$aprutil/.libs -L$pcre/.libs -L$nghttp/lib/" CFLAGS=" $CFLAGS -I$nghttp/lib/includes -march=skylake -g -ggdb -fno-builtin -fno-inline" LDFLAGS="$CFLAGS" ./configure --enable-unixd --disable-pie --enable-mods-static=few --prefix="$PREFIX" --with-mpm=event --enable-http2 --with-apr=$apr --with-apr-util=$aprutil --with-nghttp2=$nghttp --enable-nghttp2-staticlib-deps --with-pcre=$pcre/pcre-config && make clean && make -j6` , the `-march=skylake` flag fucked us over and it generated code which didn't work on my machine. I guess that is my fault for trusting a blogpost blindly.

## Tinkering around with configurations and adding modules.

Now that I have the very basic configuration working, I am going to modify the configuration file to enable some of the modules and see what happens. In addition, I realized that the fuzzing was eating at my disk space quite a lot. This was caused by logging into the access_log and error_log files, which are specified in the configuration file.

First disable logging completely. This seems like our answer: https://stackoverflow.com/questions/13552312/disabling-apache-logging-to-access-log . This also has the added benefit of improving performance, because we aren' writing to disk on each request.

Another thing is that we should also populate our htdocs directory with some files.

I actually fuzzed apache httpd before and I did this: https://github.com/personnumber3377/samplefilegenerator.git which basically just generates random files for content.

mod_expires































