# Improving mupdf fuzzer oss-fuzz

I realized that google VRP has a program where you can improve a fuzzer for some project and you can get paid for doing so:

I also realized that the `mupdf` fuzzer had some poor coverage on the svg fuzzing and also it doesn't have the barcode feature enabled by default, so let's change that...

Here is my current build.sh script:

```
#!/bin/bash -eu
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

# supp_size is unused in harfbuzz so we will avoid it being unused.
# sed -i 's/supp_size;/supp_size;(void)(supp_size);/g' ./thirdparty/harfbuzz/src/hb-subset-cff1.cc

# echo "LDFLAGS=$CXXFLAGS make -j$(nproc) HAVE_GLUT=no build=debug"


# LDFLAGS="$CXXFLAGS" make -j$(nproc) HAVE_GLUT=no build=debug \
#     $OUT/libmupdf-third.a $OUT/libmupdf.a

# LDFLAGS="$CXXFLAGS" VERBOSE=1 make VERBOSE=1 -j$(nproc) HAVE_GLUT=no build=debug OUT=$WORK $WORK/libmupdf.a $WORK/libmupdf-third.a

# LDFLAGS="$CXXFLAGS" VERBOSE=1 make VERBOSE=1 -j8 HAVE_GLUT=no build=debug barcode=yes OUT=$WORK $WORK/libmupdf.a $WORK/libmupdf-third.a


fuzz_target=pdf_fuzzer

$CXX $CXXFLAGS -std=c++11 -Iinclude \
    $SRC/pdf_fuzzer.cc -o $OUT/$fuzz_target \
    $LIB_FUZZING_ENGINE $WORK/libmupdf.a $WORK/libmupdf-third.a

mv $SRC/{*.zip,*.dict,*.options} $OUT

if [ ! -f "${OUT}/${fuzz_target}_seed_corpus.zip" ]; then
  echo "missing seed corpus"
  exit 1
fi

if [ ! -f "${OUT}/${fuzz_target}.dict" ]; then
  echo "missing dictionary"
  exit 1
fi

if [ ! -f "${OUT}/${fuzz_target}.options" ]; then
  echo "missing options"
  exit 1
fi
```

I am using this here: `LDFLAGS="$CXXFLAGS" VERBOSE=1 make VERBOSE=1 -j8 HAVE_GLUT=no build=debug barcode=yes OUT=$WORK $WORK/libmupdf.a $WORK/libmupdf-third.a` .


+And to emulate the ossfuzz fuzzing environment:

```
export CXX=clang++
export CC=clang
export CFLAGS="-fsanitize=address,undefined,fuzzer-no-link -g -v"
export CXXFLAGS="-fsanitize=address,undefined,fuzzer-no-link -g -v"

# Install dir
export WORK=/home/oof/newmu/mupdf

export OUT=/home/oof/mupdf_out2
export LIB_FUZZING_ENGINE=/usr/lib/libFuzzingEngine.a
export SRC=/home/oof/newmu/mupdf

./build.sh
```

And now to make the svg fuzzer itself, I am just going to do this stuff here:

```
/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <cstdint>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

#include <mupdf/fitz.h>

/*
static fz_image *load_html_image(fz_context *ctx, fz_archive *zip, const char *base_uri, const char *src)
{
  char path[2048];
  fz_image *img = NULL;
  fz_buffer *buf = NULL;

  fz_var(img);
  fz_var(buf);

  fz_try(ctx)
  {
    if (!strncmp(src, "data:image/jpeg;base64,", 23))
      buf = fz_new_buffer_from_base64(ctx, src+23, 0);
    else if (!strncmp(src, "data:image/png;base64,", 22))
      buf = fz_new_buffer_from_base64(ctx, src+22, 0);
    else if (!strncmp(src, "data:image/gif;base64,", 22))
      buf = fz_new_buffer_from_base64(ctx, src+22, 0);
    else
    {
      fz_strlcpy(path, base_uri, sizeof path);
      fz_strlcat(path, "/", sizeof path);
      fz_strlcat(path, src, sizeof path);
      fz_urldecode(path);
      fz_cleanname(path);
      buf = fz_read_archive_entry(ctx, zip, path);
    }
#if FZ_ENABLE_SVG
    if (strstr(src, ".svg"))
      img = fz_new_image_from_svg(ctx, buf, base_uri, zip);
    else
#endif
      img = fz_new_image_from_buffer(ctx, buf);
  }
  fz_always(ctx)
    fz_drop_buffer(ctx, buf);
  fz_catch(ctx)
  {
    fz_ignore_error(ctx);
    fz_warn(ctx, "html: cannot load image src='%s'", src);
  }

  return img;
}
*/

#define ALIGNMENT ((size_t) 16)
#define KBYTE ((size_t) 1024)
#define MBYTE (1024 * KBYTE)
#define GBYTE (1024 * MBYTE)
#define MAX_ALLOCATION (1 * GBYTE)

static size_t used;

static void *fz_limit_reached_ossfuzz(size_t oldsize, size_t size)
{
  if (oldsize == 0)
    fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte allocation: %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, size);
  else
    fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte reallocation: %zu -> %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, oldsize, size);
  fflush(0);
  return NULL;
}

static void *fz_malloc_ossfuzz(void *opaque, size_t size)
{
  char *ptr = NULL;

  if (size == 0)
    return NULL;
  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;
  if (size + ALIGNMENT > MAX_ALLOCATION - used)
    return fz_limit_reached_ossfuzz(0, size + ALIGNMENT);

  ptr = (char *) malloc(size + ALIGNMENT);
  if (ptr == NULL)
    return NULL;

  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  return ptr + ALIGNMENT;
}

static void fz_free_ossfuzz(void *opaque, void *ptr)
{
  size_t size;

  if (ptr == NULL)
    return;
  if (ptr < (void *) ALIGNMENT)
    return;

  ptr = (char *) ptr - ALIGNMENT;
  memcpy(&size, ptr, sizeof(size));

  used -= size + ALIGNMENT;
  free(ptr);
}

static void *fz_realloc_ossfuzz(void *opaque, void *old, size_t size)
{
  size_t oldsize;
  char *ptr;

  if (old == NULL)
    return fz_malloc_ossfuzz(opaque, size);
  if (old < (void *) ALIGNMENT)
    return NULL;

  if (size == 0) {
    fz_free_ossfuzz(opaque, old);
    return NULL;
  }
  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;

  old = (char *) old - ALIGNMENT;
  memcpy(&oldsize, old, sizeof(oldsize));

  if (size + ALIGNMENT > MAX_ALLOCATION - used + oldsize + ALIGNMENT)
    return fz_limit_reached_ossfuzz(oldsize + ALIGNMENT, size + ALIGNMENT);

  ptr = (char *) realloc(old, size + ALIGNMENT);
  if (ptr == NULL)
    return NULL;

  used -= oldsize + ALIGNMENT;
  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  return ptr + ALIGNMENT;
}


// Just ignore warnings and errors...

static void fz_error_ossfuzz(void *user, const char *message) {
  // Avoid unused variable warnings...
  (void*)user;
  (const char *)message;
  return;
}

static void fz_warning_ossfuzz(void *user, const char *message) {
  // Avoid unused variable warnings...
  (void*)user;
  (const char *)message;
  return;
}


static fz_alloc_context fz_alloc_ossfuzz =
{
  NULL,
  fz_malloc_ossfuzz,
  fz_realloc_ossfuzz,
  fz_free_ossfuzz
};

/*
static fz_alloc_context fz_alloc_ossfuzz =
{
  NULL,
  malloc,
  realloc,
  free
};
*/

/*
#define MAXSIZE 100000
unsigned char actual_buffer[MAXSIZE];
*/






// The variables which we need...

fz_context *ctx;
fz_image *img = NULL;
fz_buffer *buf = NULL;


int LLVMFuzzerInitialize(const uint8_t *data, size_t size) {
  // Initialize fuzzer...
  ctx = fz_new_context(&fz_alloc_ossfuzz, nullptr, FZ_STORE_DEFAULT); // Create context
  ctx->error.print = fz_error_ossfuzz;
  ctx->warn.print = fz_warning_ossfuzz;
  return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0) {
    return 0;
  }
  // unsigned char* malloced = (unsigned char*)malloc(size + 1); // Allocate the stuff...
  unsigned char* malloced = (unsigned char*)fz_malloc_ossfuzz(NULL, size + 1); // We need to call this here to get an aligned address
  memcpy(malloced, data, size); // Copy the stuff into the thing...
  *(malloced+size) = '\0'; // zero-terminated

  img = NULL;
  buf = NULL;

  used = 0;

  fz_var(img);

  fz_try(ctx) {
    // fz_register_document_handlers(ctx);
    buf = fz_new_buffer_from_data(ctx, (unsigned char*)malloced, (size_t)size + 1); // Convert to fz_buffer
    img = fz_new_image_from_svg(ctx, buf, "", NULL); // Just pass NULL here? Also we are using an empty base uri for now...

  }
  fz_always(ctx) {
    // free(malloced);
    // fz_free_ossfuzz(NULL, malloced); // Free the buffer
    fz_drop_image(ctx, img);
    fz_drop_buffer(ctx, buf);
  }
  fz_catch(ctx) {
    /*
    fz_report_error(ctx);
    fz_log_error(ctx, "error rendering pages");
    */
  }

  fz_flush_warnings(ctx);
  // fz_drop_context(ctx);

  img = NULL;
  buf = NULL;

  return 0;
}
```

After gathering a fuzzing corpus, I am now fuzzing nicely. I actually realized that the default fuzzer for oss-fuzz is actually quite poorly written, since the program does the initialization on every possible run. With the oss-fuzz fuzzer I got roughly 20 execs a second, but now with the newer fuzzer I am getting over a thousand execs a second. After fuzzing for a day or so, I didn't find any crashes, so I decided to do a coverage build and see if there are any blindspots. I put it on a google cloud compute instance for now and it should finish in around a couple of days at most. (I used afl-cov with some modifications and it seems that the thing is quite slow although I think that just running every input file individually should also work nicely. idk)...

So the coverage seems to have improved! Good! In addition to this I also implemented a fuzzer for each image file format individually too and it found a couple of neat bugs, which are yet to be disclosed.

## Implementing a fuzzer for CSS

So there is this function here: `void fz_parse_css(fz_context *ctx, fz_css *css, const char *source, const char *file)` which seems to parse css.

Maybe it is just something like this here:

```
/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <cstdint>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

extern "C" {
  #include <mupdf/fitz.h>
  #include "source/fitz/image-imp.h"
}

#define ALIGNMENT ((size_t) 16)
#define KBYTE ((size_t) 1024)
#define MBYTE (1024 * KBYTE)
#define GBYTE (1024 * MBYTE)
#define MAX_ALLOCATION (1 * GBYTE)

static size_t used;

static void *fz_limit_reached_ossfuzz(size_t oldsize, size_t size)
{
  if (oldsize == 0)
    fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte allocation: %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, size);
  else
    fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte reallocation: %zu -> %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, oldsize, size);
  fflush(0);
  return NULL;
}

static void *fz_malloc_ossfuzz(void *opaque, size_t size)
{
  char *ptr = NULL;

  if (size == 0)
    return NULL;
  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;
  if (size + ALIGNMENT > MAX_ALLOCATION - used) {
    // abort();
    return fz_limit_reached_ossfuzz(0, size + ALIGNMENT);
  }

  ptr = (char *) malloc(size + ALIGNMENT);
  if (ptr == NULL)
    return NULL;

  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  return ptr + ALIGNMENT;
}

static void fz_free_ossfuzz(void *opaque, void *ptr)
{
  size_t size;

  if (ptr == NULL)
    return;
  if (ptr < (void *) ALIGNMENT)
    return;

  ptr = (char *) ptr - ALIGNMENT;
  memcpy(&size, ptr, sizeof(size));

  used -= size + ALIGNMENT;
  free(ptr);
}

static void *fz_realloc_ossfuzz(void *opaque, void *old, size_t size)
{
  size_t oldsize;
  char *ptr;

  if (old == NULL)
    return fz_malloc_ossfuzz(opaque, size);
  if (old < (void *) ALIGNMENT)
    return NULL;

  if (size == 0) {
    fz_free_ossfuzz(opaque, old);
    return NULL;
  }
  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;

  old = (char *) old - ALIGNMENT;
  memcpy(&oldsize, old, sizeof(oldsize));

  if (size + ALIGNMENT > MAX_ALLOCATION - used + oldsize + ALIGNMENT) {
    // abort();
    return fz_limit_reached_ossfuzz(oldsize + ALIGNMENT, size + ALIGNMENT);
  }

  ptr = (char *) realloc(old, size + ALIGNMENT);
  if (ptr == NULL)
    return NULL;

  used -= oldsize + ALIGNMENT;
  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  return ptr + ALIGNMENT;
}


// Just ignore warnings and errors...

static void fz_error_ossfuzz(void *user, const char *message) {
  // Avoid unused variable warnings...
  (void*)user;
  (const char *)message;
  return;
}

static void fz_warning_ossfuzz(void *user, const char *message) {
  // Avoid unused variable warnings...
  (void*)user;
  (const char *)message;
  return;
}


static fz_alloc_context fz_alloc_ossfuzz =
{
  NULL,
  fz_malloc_ossfuzz,
  fz_realloc_ossfuzz,
  fz_free_ossfuzz
};

#include <cstdlib>
#include <cstring>
#include <string>
#include "mupdf/fitz.h"

static fz_context *ctx = nullptr;
fz_new_css(ctx);

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  ctx = fz_new_context(&fz_alloc_ossfuzz, nullptr, FZ_STORE_DEFAULT);
  ctx->error.print = fz_error_ossfuzz;
  ctx->warn.print = fz_warning_ossfuzz;
  return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  if (size == 0)
    return 0;

  // Null terminate
  (data+size-1) = '\0';
  fz_css *css = fz_new_css(ctx);

  fz_try(ctx) {
    fz_parse_css(ctx, css, data, '');
  }
  fz_always(ctx) {
    fz_drop_css(ctx, css);
  }
  fz_catch(ctx) {
    // swallow errors
  }

  fz_flush_warnings(ctx);
  return 0;
}



```

?

Ok, so let's try it out...

Whoops:

```

oof@elskun-lppri:~/mupdf_out2$ ./fuzz_css.sh
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 3502273419
INFO: Loaded 1 modules   (1136020 inline 8-bit counters): 1136020 [0x604455554440, 0x6044556699d4),
INFO: Loaded 1 PC tables (1136020 PCs): 1136020 [0x6044556699d8,0x6044567bf318),
INFO:       63 files found in css/
INFO: seed corpus: files: 63 min: 75b max: 2680170b total: 5273434b rss: 123Mb
==216171== ERROR: libFuzzer: fuzz target overwrites its const input
    #0 0x60444e317955 in __sanitizer_print_stack_trace (/home/oof/mupdf_out2/css_fuzzer+0x32ee955) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)
    #1 0x60444e38182c in fuzzer::PrintStackTrace() (/home/oof/mupdf_out2/css_fuzzer+0x335882c) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)
    #2 0x60444e366f8c in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/oof/mupdf_out2/css_fuzzer+0x333df8c) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)
    #3 0x60444e366535 in fuzzer::Fuzzer::RunOne(unsigned char const*, unsigned long, bool, fuzzer::InputInfo*, bool, bool*) (/home/oof/mupdf_out2/css_fuzzer+0x333d535) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)
    #4 0x60444e368138 in fuzzer::Fuzzer::ReadAndExecuteSeedCorpora(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile>>&) (/home/oof/mupdf_out2/css_fuzzer+0x333f138) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)
    #5 0x60444e3685b6 in fuzzer::Fuzzer::Loop(std::vector<fuzzer::SizedFile, std::allocator<fuzzer::SizedFile>>&) (/home/oof/mupdf_out2/css_fuzzer+0x333f5b6) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)
    #6 0x60444e3552e2 in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/oof/mupdf_out2/css_fuzzer+0x332c2e2) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)
    #7 0x60444e34ec36 in main (/home/oof/mupdf_out2/css_fuzzer+0x3325c36) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)
    #8 0x710c1c02a1c9 in __libc_start_call_main csu/../sysdeps/nptl/libc_start_call_main.h:58:16
    #9 0x710c1c02a28a in __libc_start_main csu/../csu/libc-start.c:360:3
    #10 0x60444e271da4 in _start (/home/oof/mupdf_out2/css_fuzzer+0x3248da4) (BuildId: 1ee2aa8c8be13e226a4ce94f4f60bf07c080321b)

SUMMARY: libFuzzer: overwrites-const-input
MS: 0 ; base unit: 0000000000000000000000000000000000000000
0x2e,0x6f,0x5a,0x64,0x4a,0x58,0x3e,0x2a,0x7b,0x64,0x69,0x73,0x70,0x6c,0x61,0x79,0x3a,0x66,0x6c,0x65,0x78,0x3b,0x68,0x65,0x69,0x67,0x68,0x74,0x3a,0x69,0x6e,0x68,0x65,0x72,0x69,0x74,0x3b,0x77,0x69,0x64,0x74,0x68,0x3a,0x69,0x6e,0x68,0x65,0x72,0x69,0x74,0x7d,0x2e,0x6f,0x5a,0x64,0x4a,0x58,0x7b,0x6f,0x76,0x65,0x72,0x66,0x6c,0x6f,0x77,0x3a,0x68,0x69,0x64,0x64,0x65,0x6e,0x7d,0xa,
.oZdJX>*{display:flex;height:inherit;width:inherit}.oZdJX{overflow:hidden}\012
artifact_prefix='./'; Test unit written to ./crash-c155b568deadf60f5b7127cdf14b7931706eb61a
Base64: Lm9aZEpYPip7ZGlzcGxheTpmbGV4O2hlaWdodDppbmhlcml0O3dpZHRoOmluaGVyaXR9Lm9aZEpYe292ZXJmbG93OmhpZGRlbn0K
oof@elskun-lppri:~/mupdf_out2$

```

I think this here is better:

```

/*
# Copyright 2018 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
*/

#include <cstdint>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>

extern "C" {
  #include <mupdf/fitz.h>
  #include "source/html/html-imp.h"
}

#define ALIGNMENT ((size_t) 16)
#define KBYTE ((size_t) 1024)
#define MBYTE (1024 * KBYTE)
#define GBYTE (1024 * MBYTE)
#define MAX_ALLOCATION (1 * GBYTE)

static size_t used;

static void *fz_limit_reached_ossfuzz(size_t oldsize, size_t size)
{
  if (oldsize == 0)
    fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte allocation: %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, size);
  else
    fprintf(stderr, "limit: %zu Mbyte used: %zu Mbyte reallocation: %zu -> %zu: limit reached\n", MAX_ALLOCATION / MBYTE, used / MBYTE, oldsize, size);
  fflush(0);
  return NULL;
}

static void *fz_malloc_ossfuzz(void *opaque, size_t size)
{
  char *ptr = NULL;

  if (size == 0)
    return NULL;
  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;
  if (size + ALIGNMENT > MAX_ALLOCATION - used) {
    // abort();
    return fz_limit_reached_ossfuzz(0, size + ALIGNMENT);
  }

  ptr = (char *) malloc(size + ALIGNMENT);
  if (ptr == NULL)
    return NULL;

  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  return ptr + ALIGNMENT;
}

static void fz_free_ossfuzz(void *opaque, void *ptr)
{
  size_t size;

  if (ptr == NULL)
    return;
  if (ptr < (void *) ALIGNMENT)
    return;

  ptr = (char *) ptr - ALIGNMENT;
  memcpy(&size, ptr, sizeof(size));

  used -= size + ALIGNMENT;
  free(ptr);
}

static void *fz_realloc_ossfuzz(void *opaque, void *old, size_t size)
{
  size_t oldsize;
  char *ptr;

  if (old == NULL)
    return fz_malloc_ossfuzz(opaque, size);
  if (old < (void *) ALIGNMENT)
    return NULL;

  if (size == 0) {
    fz_free_ossfuzz(opaque, old);
    return NULL;
  }
  if (size > SIZE_MAX - ALIGNMENT)
    return NULL;

  old = (char *) old - ALIGNMENT;
  memcpy(&oldsize, old, sizeof(oldsize));

  if (size + ALIGNMENT > MAX_ALLOCATION - used + oldsize + ALIGNMENT) {
    // abort();
    return fz_limit_reached_ossfuzz(oldsize + ALIGNMENT, size + ALIGNMENT);
  }

  ptr = (char *) realloc(old, size + ALIGNMENT);
  if (ptr == NULL)
    return NULL;

  used -= oldsize + ALIGNMENT;
  memcpy(ptr, &size, sizeof(size));
  used += size + ALIGNMENT;

  return ptr + ALIGNMENT;
}


// Just ignore warnings and errors...

static void fz_error_ossfuzz(void *user, const char *message) {
  // Avoid unused variable warnings...
  (void*)user;
  (const char *)message;
  return;
}

static void fz_warning_ossfuzz(void *user, const char *message) {
  // Avoid unused variable warnings...
  (void*)user;
  (const char *)message;
  return;
}


static fz_alloc_context fz_alloc_ossfuzz =
{
  NULL,
  fz_malloc_ossfuzz,
  fz_realloc_ossfuzz,
  fz_free_ossfuzz
};

#include <cstdlib>
#include <cstring>
#include <string>
#include "mupdf/fitz.h"

static fz_context *ctx = nullptr;

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
  ctx = fz_new_context(&fz_alloc_ossfuzz, nullptr, FZ_STORE_DEFAULT);
  ctx->error.print = fz_error_ossfuzz;
  ctx->warn.print = fz_warning_ossfuzz;
  return 0;
}
#define MAX_SIZE 100000
char fuzz_buf[MAX_SIZE];

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) { // Can not use const in data, because null termination...
  if (size == 0 || size > MAX_SIZE-1)
    return 0;

  // Copy to make sure it is null terminated.
  memset(fuzz_buf, 0, sizeof(fuzz_buf));
  memcpy(fuzz_buf, data, size);

  fz_css *css = fz_new_css(ctx);

  fz_try(ctx) {
    fz_parse_css(ctx, css, (const char *)fuzz_buf, "");
  }
  fz_always(ctx) {
    fz_drop_css(ctx, css);
  }
  fz_catch(ctx) {
    // swallow errors
  }

  fz_flush_warnings(ctx);
  return 0;
}

```

## Results

Ok, so I managed to find a couple of OOM bugs and one out-of-bounds read, so nothing major, but still quite a nice attempt. Maybe I will come back to this fuzzing project in the future possibly?


## TODO

- Add specific fuzzers for html and css. (Done)
- Add specific fuzzer for xps (Done)

- Add EPUB fuzzer...
- Add XREF section fuzzer.
- Add journal fuzzing. (see https://storage.googleapis.com/oss-fuzz-coverage/mupdf/reports-by-target/20250724/pdf_fuzzer/linux/src/mupdf/source/pdf/pdf-write.c.html#L3061 for poor coverage. There is the function called mupdf/pdf/document.h:void pdf_read_journal(fz_context *ctx, pdf_document *doc, fz_stream *stm);)

- Add format aware fuzzing.
- Disable image and font rendering when fuzzing PDF rendering to speed up fuzzing. Those are largely handled by third party libraries...



