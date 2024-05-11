
# Fuzzing git command line parameters

Hi!

I was bored and I was searching for a suitable fuzzing target. Now after looking at the man page for git, there are plenty of interesting looking command line options. In addition to this, if you look at the git source code here: https://github.com/git/git/tree/master/oss-fuzz , there isn't a fuzzer for command line parameters. Then, if you look at the security tab on the repository, there are gems like this: https://github.com/git/git/security/advisories/GHSA-475x-2q3q-hvwq .

## The usual setup

As always, I am going to just compile with afl-clang-fast and with address sanitizer and undefined behaviour sanitizer.

In addition to the usual setup, I must also enable fuzzing of command line parameters.

Here are my modifications to common-main.c :

```
diff --git a/common-main.c b/common-main.c
index 033778b3c5..f912f0be33 100644
--- a/common-main.c
+++ b/common-main.c
@@ -7,6 +7,10 @@
 #include "strbuf.h"
 #include "trace2.h"
 
+// Needed for fuzzing
+
+#include "/home/cyberhacker/Asioita/newaflfuzz/AFLplusplus/utils/argv_fuzzing/argv-fuzz-inl.h"
+
 /*
  * Many parts of Git have subprograms communicate via pipe, expect the
  * upstream of a pipe to die with SIGPIPE when the downstream of a
@@ -28,6 +32,9 @@ static void restore_sigpipe_to_default(void)
 	signal(SIGPIPE, SIG_DFL);
 }
 
+
+__AFL_FUZZ_INIT();
+
 int main(int argc, const char **argv)
 {
 	int result;
@@ -59,7 +66,31 @@ int main(int argc, const char **argv)
 	if (!strbuf_getcwd(&tmp))
 		tmp_original_cwd = strbuf_detach(&tmp, NULL);
 
-	result = cmd_main(argc, argv);
+
+	// AFL_INIT_SET0("a.out");
+
+	__AFL_INIT();
+
+
+	unsigned char *buf = __AFL_FUZZ_TESTCASE_BUF;
+
+
+	while (__AFL_LOOP(100000)) {
+
+		int len = __AFL_FUZZ_TESTCASE_LEN;
+
+		//AFL_INIT_SET0("git");
+		AFL_INIT_SET0_PERSISTENT("git", buf);
+		//printf("Showing command line arguments: \n");
+		//for(int i=0;i<argc-1;i++)
+		//	printf("%s",argv[i]);
+
+		//printf("Done!\n");
+		result = cmd_main(argc, argv);
+
+
+	}
+
 
 	/* Not exit(3), but a wrapper calling our common_exit() */
 	exit(result);

```

I initialized my fuzzer with this data:

```
log --pretty="format:%H"
```

inside a file and I am going to let it run for a bit.


## Any crashes?

Not yet, but I will keep fuzzing for a while until I get some crashes.




