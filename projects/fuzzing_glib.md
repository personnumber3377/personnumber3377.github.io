# Fuzzing glib

First the usual setup:

```
FROM aflplusplus/aflplusplus

RUN apt update && apt install -y libnghttp2-dev libsqlite3-dev libpsl-dev glib-networking tmux

WORKDIR /fuzzing/

##Getting libsoup, compile it with afl-clang-fast and asan
RUN git clone https://gitlab.gnome.org/GNOME/libsoup.git libsoup
ENV CC=/AFLplusplus/afl-clang-fast
ENV CXX=/AFLplusplus/afl-clang-fast++
ENV CFLAGS='-fsanitize=address'
ENV CXXFLAGS='-fsanitize=address'
WORKDIR libsoup
RUN meson setup _build  --prefix /fuzzing/build_libsoup && meson install -C _build

WORKDIR /fuzzing/
```

And maybe something like this here:

```
// gmarkup_afl_fuzzer.c
// Fuzz GLib's GMarkup parser w/o files. AFL++ persistent mode supported.
#include <glib.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#ifdef __AFL_HAVE_MANUAL_CONTROL
  #include "afl-fuzz.h"
#endif

// ---- Minimal no-op callbacks (you can enrich if you want to exercise more) ----
static void cb_start (GMarkupParseContext *ctx, const gchar *name,
                      const gchar **attr_names, const gchar **attr_values,
                      gpointer user_data, GError **error) { (void)ctx; (void)name; (void)attr_names; (void)attr_values; (void)user_data; (void)error; }
static void cb_end   (GMarkupParseContext *ctx, const gchar *name,
                      gpointer user_data, GError **error) { (void)ctx; (void)name; (void)user_data; (void)error; }
static void cb_text  (GMarkupParseContext *ctx, const gchar *text, gsize text_len,
                      gpointer user_data, GError **error) { (void)ctx; (void)text; (void)text_len; (void)user_data; (void)error; }
// passthrough & error callbacks optional; leaving NULL is fine

static const GMarkupParser parser = {
  .start_element = cb_start,
  .end_element   = cb_end,
  .text          = cb_text,
  .passthrough   = NULL,
  .error         = NULL,
};

// ---- Helpers ----
static int parse_null_terminated(const char *buf_with_nul, gsize len, GMarkupParseFlags flags) {
  (void)len; // length unused in this mode
  GError *err = NULL;
  GMarkupParseContext *ctx = g_markup_parse_context_new(&parser, flags, NULL, NULL);
  if (!g_markup_parse_context_parse(ctx, buf_with_nul, -1, &err) ||
      !g_markup_parse_context_end_parse(ctx, &err)) {
    g_markup_parse_context_free(ctx);
    if (err) g_error_free(err);
    return -1;
  }
  g_markup_parse_context_free(ctx);
  return 0;
}

static int parse_in_chunks(const char *buf, gsize len, gsize chunk_sz, GMarkupParseFlags flags) {
  GError *err = NULL;
  GMarkupParseContext *ctx = g_markup_parse_context_new(&parser, flags, NULL, NULL);
  gsize pos = 0;
  while (pos < len) {
    gsize c = chunk_sz;
    if (c > len - pos) c = len - pos;
    if (!g_markup_parse_context_parse(ctx, buf + pos, c, &err)) {
      g_markup_parse_context_free(ctx);
      if (err) g_error_free(err);
      return -1;
    }
    pos += c;
  }
  if (!g_markup_parse_context_end_parse(ctx, &err)) {
    g_markup_parse_context_free(ctx);
    if (err) g_error_free(err);
    return -1;
  }
  g_markup_parse_context_free(ctx);
  return 0;
}

static void test_one_input(const uint8_t *data, size_t size) {
  // Make warnings/criticals crash so AFL catches them.
  g_log_set_always_fatal(G_LOG_LEVEL_WARNING | G_LOG_LEVEL_CRITICAL | G_LOG_LEVEL_ERROR);

  // (Optional) cap size to keep runs snappy
  const size_t MAX = 1 << 20; // 1 MiB
  if (size > MAX) size = MAX;

  // Prepare buffers (with and without trailing NUL)
  char *with_nul  = (char*)g_malloc(size + 1);
  char *no_nul    = (char*)g_malloc(size);
  if (!with_nul || (!no_nul && size > 0)) {
    abort();
  }
  if (size) memcpy(with_nul, data, size);
  if (size) memcpy(no_nul,   data, size);
  with_nul[size] = '\0';

  const gsize chunk_sizes[] = { 1, 2, 5, 12, 1024 };
  const GMarkupParseFlags flag_sets[] = {
    0,
    G_MARKUP_TREAT_CDATA_AS_TEXT,
    G_MARKUP_PREFIX_ERROR_POSITION,
    G_MARKUP_IGNORE_QUALIFIED,
    G_MARKUP_TREAT_CDATA_AS_TEXT | G_MARKUP_PREFIX_ERROR_POSITION,
    G_MARKUP_TREAT_CDATA_AS_TEXT | G_MARKUP_IGNORE_QUALIFIED,
    G_MARKUP_PREFIX_ERROR_POSITION | G_MARKUP_IGNORE_QUALIFIED,
    G_MARKUP_TREAT_CDATA_AS_TEXT | G_MARKUP_PREFIX_ERROR_POSITION | G_MARKUP_IGNORE_QUALIFIED,
  };

  for (guint f = 0; f < G_N_ELEMENTS(flag_sets); f++) {
    guint n_failures = 0, n_tests = 0;

    // 1) NUL-terminated, length = -1
    if (parse_null_terminated(with_nul, size, flag_sets[f]) != 0) n_failures++;
    n_tests++;

    // 2) Explicit length, NUL present
    if (parse_in_chunks(with_nul, size, size, flag_sets[f]) != 0) n_failures++;
    n_tests++;

    // 3) Explicit length, NO NUL
    if (parse_in_chunks(no_nul, size, size, flag_sets[f]) != 0) n_failures++;
    n_tests++;

    // 4) Various chunk sizes (explicit length)
    for (guint i = 0; i < G_N_ELEMENTS(chunk_sizes); i++) {
      gsize cs = chunk_sizes[i];
      if (parse_in_chunks(with_nul, size, cs, flag_sets[f]) != 0) n_failures++;
      n_tests++;
    }

    // Invariant: either all success or all fail, otherwise it's a bug.
    if (n_failures > 0 && n_failures < n_tests) {
      abort(); // AFL will flag this input
    }
  }

  g_free(with_nul);
  g_free(no_nul);
}

#ifndef __AFL_HAVE_MANUAL_CONTROL
// Fallback: read from stdin (still no file I/O). Works with plain AFL too.
int main(void) {
  uint8_t *buf = NULL;
  size_t cap = 0, sz = 0;
  for (;;) {
    if (sz == cap) {
      cap = cap ? cap * 2 : 4096;
      buf = (uint8_t*)realloc(buf, cap);
      if (!buf) return 0;
    }
    size_t n = fread(buf + sz, 1, cap - sz, stdin);
    sz += n;
    if (n == 0) break;
  }
  test_one_input(buf, sz);
  free(buf);
  return 0;
}
#else
// AFL++ persistent shared-memory fuzzing (no files needed)
int main(void) {
  __AFL_INIT();
  while (__AFL_LOOP(1000)) {
    size_t len = __AFL_FUZZ_TESTCASE_LEN;
    const uint8_t *ptr = __AFL_FUZZ_TESTCASE_BUF;
    test_one_input(ptr, len);
  }
  return 0;
}
#endif
```





