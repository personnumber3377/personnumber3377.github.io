# Fuzzing ffmpeg avfilter graphs

I recently fuzzed a library called libmysofa which is used in ffmpeg and that got me thinking that there is still plenty of more "gold" to be found. The ffmpeg codebase is largely a mess and requires some work.

Looking through the codebase as of writing this blog post, there are fuzzers in ffmpeg, but there does not appear to be one for avfilter graphs which are used in a couple of places in the codebase.







Looking at the code we may need to use these functions here:

```

AVFilterGraph *avfilter_graph_alloc(void)
{
    FFFilterGraph *graph = av_mallocz(sizeof(*graph));
    AVFilterGraph *ret;

    if (!graph)
        return NULL;

    ret = &graph->p;
    ret->av_class = &filtergraph_class;
    av_opt_set_defaults(ret);
    ff_framequeue_global_init(&graph->frame_queues);

    return ret;
}

void ff_filter_graph_remove_filter(AVFilterGraph *graph, AVFilterContext *filter)
{
    int i, j;
    for (i = 0; i < graph->nb_filters; i++) {
        if (graph->filters[i] == filter) {
            FFSWAP(AVFilterContext*, graph->filters[i],
                   graph->filters[graph->nb_filters - 1]);
            graph->nb_filters--;
            filter->graph = NULL;
            for (j = 0; j<filter->nb_outputs; j++)
                if (filter->outputs[j])
                    ff_filter_link(filter->outputs[j])->graph = NULL;

            return;
        }
    }
}

void avfilter_graph_free(AVFilterGraph **graphp)
{
    AVFilterGraph *graph = *graphp;
    FFFilterGraph *graphi = fffiltergraph(graph);

    if (!graph)
        return;

    while (graph->nb_filters)
        avfilter_free(graph->filters[0]);

    ff_graph_thread_free(graphi);

    av_freep(&graphi->sink_links);

    av_opt_free(graph);

    av_freep(&graph->filters);
    av_freep(graphp);
}

```

to allocate and free the graphs during fuzzing...

## Adding a fork

Here is my fork which adds a fuzzer for the graphs: https://github.com/personnumber3377/FFmpeg

To build ffmpeg you can just follow the instructions here: https://trac.ffmpeg.org/wiki/CompilationGuide





```
sudo apt-get -y install \
  autoconf \
  automake \
  build-essential \
  cmake \
  git-core \
  libass-dev \
  libfreetype6-dev \
  libgnutls28-dev \
  libmp3lame-dev \
  libsdl2-dev \
  libtool \
  libva-dev \
  libvdpau-dev \
  libvorbis-dev \
  libxcb1-dev \
  libxcb-shm0-dev \
  libxcb-xfixes0-dev \
  meson \
  ninja-build \
  pkg-config \
  texinfo \
  wget \
  yasm \
  zlib1g-dev
```

Actually fuck that. To compile fuzzers we need to follow the instructions in one of the fuzzing files for example target_dec_fuzzer has this:

```

/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* Targeted fuzzer that targets specific codecs depending on two
   compile-time flags.
  INSTRUCTIONS:

  * Get the very fresh clang, e.g. see http://libfuzzer.info#versions
  * Get and build libFuzzer:
     svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer
     ./Fuzzer/build.sh
  * build ffmpeg for fuzzing:
    FLAGS="-fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp -g" CC="clang $FLAGS" CXX="clang++ $FLAGS" ./configure  --disable-x86asm
    make clean && make -j
  * build the fuzz target.
    Choose the value of FFMPEG_CODEC (e.g. AV_CODEC_ID_DVD_SUBTITLE) and
    choose one of FUZZ_FFMPEG_VIDEO, FUZZ_FFMPEG_AUDIO, FUZZ_FFMPEG_SUBTITLE.
    clang -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp tools/target_dec_fuzzer.c -o target_dec_fuzzer -I.   -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO ../../libfuzzer/libFuzzer.a   -Llibavcodec -Llibavdevice -Llibavfilter -Llibavformat -Llibavutil -Llibpostproc -Llibswscale -Llibswresample -Wl,--as-needed -Wl,-z,noexecstack -Wl,--warn-common -Wl,-rpath-link=:libpostproc:libswresample:libswscale:libavfilter:libavdevice:libavformat:libavcodec:libavutil -lavdevice -lavfilter -lavformat -lavcodec -lswresample -lswscale -lavutil -ldl -lxcb -lxcb-shm -lxcb -lxcb-xfixes  -lxcb -lxcb-shape -lxcb -lX11 -lasound -lm -lbz2 -lz -pthread
  * create a corpus directory and put some samples there (empty dir is ok too):
    mkdir CORPUS && cp some-files CORPUS

  * Run fuzzing:
    ./target_dec_fuzzer -max_len=100000 CORPUS

   More info:
   http://libfuzzer.info
   http://tutorial.libfuzzer.info
   https://github.com/google/oss-fuzz
   http://lcamtuf.coredump.cx/afl/
   https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html
*/

```

so I made this build_fuzz.sh script here:

```

#!/bin/sh
FLAGS="-fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp -g" CC="clang $FLAGS" CXX="clang++ $FLAGS" ./configure  --disable-x86asm
make clean && make -j$(nproc) # Build


```

and then to compile the fuzzer binary, we need to run this monstrosity:

```
clang -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp tools/target_dec_fuzzer.c -o target_dec_fuzzer -I.   -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO ../../libfuzzer/libFuzzer.a   -Llibavcodec -Llibavdevice -Llibavfilter -Llibavformat -Llibavutil -Llibpostproc -Llibswscale -Llibswresample -Wl,--as-needed -Wl,-z,noexecstack -Wl,--warn-common -Wl,-rpath-link=:libpostproc:libswresample:libswscale:libavfilter:libavdevice:libavformat:libavcodec:libavutil -lavdevice -lavfilter -lavformat -lavcodec -lswresample -lswscale -lavutil -ldl -lxcb -lxcb-shm -lxcb -lxcb-xfixes  -lxcb -lxcb-shape -lxcb -lX11 -lasound -lm -lbz2 -lz -pthread
```

but for my own tools/target_graph_fuzzer.c instead...

Actually I just modified it to this:

```

clang -fsanitize=address,undefined,fuzzer -fsanitize-coverage=trace-pc-guard,trace-cmp tools/target_graph_fuzzer.c -o target_graph_fuzzer -I.   -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO   -Llibavcodec -Llibavdevice -Llibavfilter -Llibavformat -Llibavutil -Llibpostproc -Llibswscale -Llibswresample -Wl,--as-needed -Wl,-z,noexecstack -Wl,--warn-common -Wl,-rpath-link=:libpostproc:libswresample:libswscale:libavfilter:libavdevice:libavformat:libavcodec:libavutil -lavdevice -lavfilter -lavformat -lavcodec -lswresample -lswscale -lavutil -ldl -lxcb -lxcb-shm -lxcb -lxcb-xfixes  -lxcb -lxcb-shape -lxcb -lX11 -lasound -lm -lbz2 -lz -pthread

```

let's test it out...

so my final build script is this:

```

#!/bin/sh
FLAGS="-fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp -g" CC="clang $FLAGS" CXX="clang++ $FLAGS" ./configure  --disable-x86asm
make clean && make -j$(nproc) # Build
clang -fsanitize=address,undefined,fuzzer -fsanitize-coverage=trace-pc-guard,trace-cmp tools/target_graph_fuzzer.c -o target_graph_fuzzer -I.   -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO   -Llibavcodec -Llibavdevice -Llibavfilter -Llibavformat -Llibavutil -Llibpostproc -Llibswscale -Llibswresample -Wl,--as-needed -Wl,-z,noexecstack -Wl,--warn-common -Wl,-rpath-link=:libpostproc:libswresample:libswscale:libavfilter:libavdevice:libavformat:libavcodec:libavutil -lavdevice -lavfilter -lavformat -lavcodec -lswresample -lswscale -lavutil -ldl -lxcb -lxcb-shm -lxcb -lxcb-xfixes  -lxcb -lxcb-shape -lxcb -lX11 -lasound -lm -lbz2 -lz -pthread

```


Here is my final fuzzer:

```

/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* Targeted fuzzer that targets specific codecs depending on two
   compile-time flags.
  INSTRUCTIONS:

  * Get the very fresh clang, e.g. see http://libfuzzer.info#versions
  * Get and build libFuzzer:
     svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer
     ./Fuzzer/build.sh
  * build ffmpeg for fuzzing:
    FLAGS="-fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp -g" CC="clang $FLAGS" CXX="clang++ $FLAGS" ./configure  --disable-x86asm
    make clean && make -j
  * build the fuzz target.
    Choose the value of FFMPEG_CODEC (e.g. AV_CODEC_ID_DVD_SUBTITLE) and
    choose one of FUZZ_FFMPEG_VIDEO, FUZZ_FFMPEG_AUDIO, FUZZ_FFMPEG_SUBTITLE.
    clang -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp tools/target_dec_fuzzer.c -o target_dec_fuzzer -I.   -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO ../../libfuzzer/libFuzzer.a   -Llibavcodec -Llibavdevice -Llibavfilter -Llibavformat -Llibavutil -Llibpostproc -Llibswscale -Llibswresample -Wl,--as-needed -Wl,-z,noexecstack -Wl,--warn-common -Wl,-rpath-link=:libpostproc:libswresample:libswscale:libavfilter:libavdevice:libavformat:libavcodec:libavutil -lavdevice -lavfilter -lavformat -lavcodec -lswresample -lswscale -lavutil -ldl -lxcb -lxcb-shm -lxcb -lxcb-xfixes  -lxcb -lxcb-shape -lxcb -lX11 -lasound -lm -lbz2 -lz -pthread
  * create a corpus directory and put some samples there (empty dir is ok too):
    mkdir CORPUS && cp some-files CORPUS

  * Run fuzzing:
    ./target_dec_fuzzer -max_len=100000 CORPUS

   More info:
   http://libfuzzer.info
   http://tutorial.libfuzzer.info
   https://github.com/google/oss-fuzz
   http://lcamtuf.coredump.cx/afl/
   https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html
*/

#include "config.h"
#include "libavutil/avassert.h"
#include "libavutil/avstring.h"
#include "libavutil/cpu.h"
#include "libavutil/imgutils.h"
#include "libavutil/intreadwrite.h"
#include "libavutil/mem.h"

#include "libavcodec/avcodec.h"
#include "libavcodec/bytestream.h"
#include "libavcodec/codec_internal.h"
#include "libavformat/avformat.h"

//For FF_SANE_NB_CHANNELS, so we dont waste energy testing things that will get instantly rejected
#include "libavcodec/internal.h"

// These next includes are taken from tools/uncoded_frame.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libavutil/avassert.h"
#include "libavutil/mem.h"
#include "libavdevice/avdevice.h"
#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavformat/avformat.h"
#include "libavcodec/codec_id.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // This fuzzer is based on the source found in tools/uncoded_frame.c
    int ret;

    /*

    char *in_graph_desc, **out_dev_name;
    int nb_out_dev = 0, nb_streams = 0;
    AVFilterGraph *in_graph = NULL;
    Stream *streams = NULL, *st;
    AVFrame *frame = NULL;
    int i, j, run = 1, ret;

    //av_log_set_level(AV_LOG_DEBUG);

    if (argc < 3) {
        av_log(NULL, AV_LOG_ERROR,
               "Usage: %s filter_graph dev:out [dev2:out2...]\n\n"
               "Examples:\n"
               "%s movie=file.nut:s=v+a xv:- alsa:default\n"
               "%s movie=file.nut:s=v+a uncodedframecrc:pipe:0\n",
               argv[0], argv[0], argv[0]);
        exit(1);
    }
    in_graph_desc = argv[1];
    out_dev_name = argv + 2;
    nb_out_dev = argc - 2;

    avdevice_register_all();


    if (!(in_graph = avfilter_graph_alloc())) {
        ret = AVERROR(ENOMEM);
        av_log(NULL, AV_LOG_ERROR, "Unable to alloc graph graph: %s\n",
               av_err2str(ret));
        goto fail;
    }
    ret = avfilter_graph_parse_ptr(in_graph, in_graph_desc, NULL, NULL, NULL);
    if (ret < 0) {
        av_log(NULL, AV_LOG_ERROR, "Unable to parse graph: %s\n",
               av_err2str(ret));
        goto fail;
    }
    */
    AVFilterGraph *in_graph = NULL;

    if (!(in_graph = avfilter_graph_alloc())) { // If allocation fails, just bail out here early.
        return 0;
    }

    ret = avfilter_graph_parse_ptr(in_graph, data, NULL, NULL, NULL);

    // Now free the graph object to avoid memory leaks...

    avfilter_graph_free(&in_graph); // This is a bit weird that this expects a pointer but idk....


    return 0;
}


```

after trying to compile I get a shit ton of linker errors here:

```

tools/target_graph_fuzzer.c:130:46: warning: passing 'const uint8_t *' (aka 'const unsigned char *') to parameter of type 'const char *' converts between pointers to integer types where one is of the unique plain 'char' type and the other is not [-Wpointer-sign]
  130 |     ret = avfilter_graph_parse_ptr(in_graph, data, NULL, NULL, NULL);
      |                                              ^~~~
./libavfilter/avfilter.h:996:64: note: passing argument to parameter 'filters' here
  996 | int avfilter_graph_parse_ptr(AVFilterGraph *graph, const char *filters,
      |                                                                ^
1 warning generated.
/usr/bin/ld: /usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.a(asan_interceptors_vfork.S.o): warning: common of `__interception::real_vfork' overridden by definition from /usr/lib/llvm-18/lib/clang/18/lib/linux/libclang_rt.asan-x86_64.a(asan_interceptors.cpp.o)
/usr/bin/ld: libavfilter/libavfilter.a(vf_deinterlace_vaapi.o): in function `deint_vaapi_build_filter_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:88:(.text+0x4b): undefined reference to `vaQueryVideoProcFilterCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:132:(.text+0x11a): undefined reference to `vaQueryVideoProcPipelineCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:94:(.text+0x2b2): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:137:(.text+0x358): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vf_deinterlace_vaapi.o): in function `deint_vaapi_filter_frame':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:257:(.text+0xa05): undefined reference to `vaMapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:274:(.text+0xa45): undefined reference to `vaUnmapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:276:(.text+0xae3): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:329:(.text+0xc05): undefined reference to `vaUnmapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_deinterlace_vaapi.c:260:(.text+0xc45): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vf_misc_vaapi.o): in function `denoise_vaapi_build_filter_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_misc_vaapi.c:72:(.text+0x48): undefined reference to `vaQueryVideoProcFilterCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_misc_vaapi.c:76:(.text+0xdd): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vf_misc_vaapi.o): in function `sharpness_vaapi_build_filter_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_misc_vaapi.c:102:(.text+0x158): undefined reference to `vaQueryVideoProcFilterCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_misc_vaapi.c:106:(.text+0x1ed): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vf_overlay_vaapi.o): in function `overlay_vaapi_build_filter_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_overlay_vaapi.c:136:(.text+0x55b): undefined reference to `vaQueryVideoProcPipelineCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_overlay_vaapi.c:141:(.text+0x5db): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vf_procamp_vaapi.o): in function `procamp_vaapi_build_filter_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_procamp_vaapi.c:78:(.text+0x251): undefined reference to `vaQueryVideoProcFilterCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_procamp_vaapi.c:82:(.text+0x406): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vf_tonemap_vaapi.o): in function `tonemap_vaapi_build_filter_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_tonemap_vaapi.c:276:(.text+0x83): undefined reference to `vaQueryVideoProcFilterCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_tonemap_vaapi.c:281:(.text+0x1ee): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vf_tonemap_vaapi.o): in function `tonemap_vaapi_set_filter_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_tonemap_vaapi.c:241:(.text+0x439): undefined reference to `vaMapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_tonemap_vaapi.c:252:(.text+0x48a): undefined reference to `vaUnmapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_tonemap_vaapi.c:244:(.text+0xad4): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_tonemap_vaapi.c:254:(.text+0xb36): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vf_transpose_vaapi.o): in function `transpose_vaapi_build_filter_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_transpose_vaapi.c:47:(.text+0x354): undefined reference to `vaQueryVideoProcPipelineCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vf_transpose_vaapi.c:52:(.text+0x4c9): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(tiff.o): in function `tiff_uncompress_lzma':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/tiff.c:574:(.text+0x1b0e): undefined reference to `lzma_stream_decoder'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/tiff.c:579:(.text+0x1b23): undefined reference to `lzma_code'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/tiff.c:580:(.text+0x1b2e): undefined reference to `lzma_end'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode_av1.o): in function `vaapi_encode_av1_init':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode_av1.c:900:(.text.unlikely+0x14a): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode_av1.c:917:(.text.unlikely+0x1b4): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode_av1.c:922:(.text.unlikely+0x1c3): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode_av1.c:935:(.text.unlikely+0x24d): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode_h264.o): in function `vaapi_encode_h264_configure':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode_h264.c:925:(.text.unlikely+0x36c): undefined reference to `vaQueryVendorString'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode_h265.o): in function `vaapi_encode_h265_get_encoder_caps':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode_h265.c:912:(.text.unlikely+0x268): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode_h265.c:926:(.text.unlikely+0x2db): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_free_output_buffer':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2060:(.text+0x80): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_alloc_output_buffer':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2077:(.text+0xf5): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2082:(.text+0x12b): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_get_coded_buffer_size':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:665:(.text+0x191): undefined reference to `vaMapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:677:(.text+0x1c0): undefined reference to `vaUnmapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:668:(.text+0x1ea): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:679:(.text+0x213): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_make_packed_header':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:60:(.text+0x2e5): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:71:(.text+0x33b): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:64:(.text+0x3b7): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:75:(.text+0x3eb): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_make_param_buffer':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:101:(.text+0x49f): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:104:(.text+0x503): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_get_coded_buffer_data':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:696:(.text+0x579): undefined reference to `vaMapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:713:(.text+0x5dc): undefined reference to `vaUnmapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:699:(.text+0x60c): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:715:(.text+0x635): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_wait':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:160:(.text+0x783): undefined reference to `vaSyncBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:171:(.text+0x7be): undefined reference to `vaSyncSurface'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:173:(.text+0x7cc): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:164:(.text+0x7f4): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_issue':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:642:(.text+0xb3f): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:590:(.text+0x10ec): undefined reference to `vaBeginPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:599:(.text+0x1113): undefined reference to `vaRenderPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:608:(.text+0x1133): undefined reference to `vaEndPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:625:(.text+0x1177): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:628:(.text+0x16c6): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:593:(.text+0x17b1): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:639:(.text+0x17e2): undefined reference to `vaEndPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:602:(.text+0x1924): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:610:(.text+0x199e): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_wait':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:160:(.text+0x1c75): undefined reference to `vaSyncBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:171:(.text+0x1d2f): undefined reference to `vaSyncSurface'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:173:(.text+0x1d41): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:164:(.text+0x1e18): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_profile_entrypoint':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:980:(.text.unlikely+0x18b): undefined reference to `vaMaxNumProfiles'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:986:(.text.unlikely+0x1d2): undefined reference to `vaQueryConfigProfiles'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:988:(.text.unlikely+0x1e1): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1010:(.text.unlikely+0x2a0): undefined reference to `vaProfileStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1040:(.text.unlikely+0x380): undefined reference to `vaMaxNumEntrypoints'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1046:(.text.unlikely+0x3bf): undefined reference to `vaQueryConfigEntrypoints'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1049:(.text.unlikely+0x3da): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1073:(.text.unlikely+0x478): undefined reference to `vaEntrypointStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1098:(.text.unlikely+0x547): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1102:(.text.unlikely+0x554): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_init_rate_control':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1235:(.text.unlikely+0x6c8): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1239:(.text.unlikely+0x6d6): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_init_gop_structure':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1643:(.text.unlikely+0x1048): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1648:(.text.unlikely+0x1057): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1667:(.text.unlikely+0x10e9): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1672:(.text.unlikely+0x10fa): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_init_slice_structure':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1854:(.text.unlikely+0x130e): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1859:(.text.unlikely+0x131b): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_init_roi':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2026:(.text.unlikely+0x16e5): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2031:(.text.unlikely+0x16f6): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_init_packed_headers':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1917:(.text.unlikely+0x1762): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1922:(.text.unlikely+0x1775): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_init_quality':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1979:(.text.unlikely+0x18b5): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1984:(.text.unlikely+0x18c2): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `vaapi_encode_init_max_frame_size':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1591:(.text.unlikely+0x19cc): undefined reference to `vaGetConfigAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:1597:(.text.unlikely+0x19e4): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `ff_vaapi_encode_init':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2226:(.text.unlikely+0x1abf): undefined reference to `vaCreateConfig'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2231:(.text.unlikely+0x1acc): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2242:(.text.unlikely+0x1bde): undefined reference to `vaCreateContext'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2249:(.text.unlikely+0x1bed): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2324:(.text.unlikely+0x1dc8): undefined reference to `vaSyncBuffer'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_encode.o): in function `ff_vaapi_encode_close':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2361:(.text.unlikely+0x1eed): undefined reference to `vaDestroyContext'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_encode.c:2367:(.text.unlikely+0x1f16): undefined reference to `vaDestroyConfig'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `ff_vaapi_vpp_pipeline_uninit':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51:(.text+0x7dd): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51:(.text+0x800): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51:(.text+0x823): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:58:(.text+0x86f): undefined reference to `vaDestroyContext'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:63:(.text+0x88a): undefined reference to `vaDestroyConfig'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51:(.text+0x8b8): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51:(.text+0x8d8): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51:(.text+0x8f8): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51:(.text+0x918): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51:(.text+0x938): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o):/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:51: more undefined references to `vaDestroyBuffer' follow
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `ff_vaapi_vpp_config_output':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:140:(.text+0xb01): undefined reference to `vaCreateConfig'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:143:(.text+0xbe3): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:227:(.text+0xd7e): undefined reference to `vaCreateContext'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:233:(.text+0xeb8): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `vaapi_vpp_colour_properties':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:448:(.text+0xfd3): undefined reference to `vaQueryVideoProcPipelineCaps'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:452:(.text+0x133e): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `ff_vaapi_vpp_make_param_buffers':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:594:(.text+0x13f7): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:597:(.text+0x1463): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `ff_vaapi_vpp_render_pictures':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:656:(.text+0x153a): undefined reference to `vaBeginPicture'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `vaapi_vpp_render_single_pipeline_buffer':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:617:(.text+0x1592): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:629:(.text+0x15cf): undefined reference to `vaRenderPicture'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `ff_vaapi_vpp_render_pictures':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:671:(.text+0x160a): undefined reference to `vaEndPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:682:(.text+0x1644): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:684:(.text+0x1655): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:656:(.text+0x16c0): undefined reference to `vaBeginPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:659:(.text+0x16cd): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:671:(.text+0x1709): undefined reference to `vaEndPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:673:(.text+0x171a): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:701:(.text+0x174c): undefined reference to `vaEndPicture'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `vaapi_vpp_render_single_pipeline_buffer':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:621:(.text+0x1759): undefined reference to `vaErrorStr'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `ff_vaapi_vpp_render_pictures':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:699:(.text+0x1797): undefined reference to `vaRenderPicture'
/usr/bin/ld: libavfilter/libavfilter.a(vaapi_vpp.o): in function `vaapi_vpp_render_single_pipeline_buffer':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/vaapi_vpp.c:631:(.text+0x17a4): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `ff_vaapi_decode_destroy_buffers':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:146:(.text+0x41): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:156:(.text+0x8f): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:159:(.text+0x9c): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:149:(.text+0xe3): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `vaapi_decode_make_config':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:500:(.text+0x198): undefined reference to `vaMaxNumProfiles'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:508:(.text+0x1c7): undefined reference to `vaQueryConfigProfiles'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:572:(.text+0x339): undefined reference to `vaCreateConfig'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `vaapi_decode_find_best_format':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:332:(.text+0x430): undefined reference to `vaQuerySurfaceAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:344:(.text+0x474): undefined reference to `vaQuerySurfaceAttributes'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `vaapi_decode_make_config':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:661:(.text+0x58c): undefined reference to `vaDestroyConfig'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:511:(.text+0x5f3): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:576:(.text+0x624): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `vaapi_decode_find_best_format':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:347:(.text+0x7ed): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:335:(.text+0x822): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `ff_vaapi_decode_make_param_buffer':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:57:(.text+0x8df): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:61:(.text+0x9a4): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `ff_vaapi_decode_make_slice_buffer':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:103:(.text+0xa6b): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:117:(.text+0xad1): undefined reference to `vaCreateBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:108:(.text+0xba3): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:122:(.text+0xbd4): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:125:(.text+0xc08): undefined reference to `vaDestroyBuffer'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `ff_vaapi_decode_issue':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:181:(.text+0xc8c): undefined reference to `vaBeginPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:190:(.text+0xcb0): undefined reference to `vaRenderPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:199:(.text+0xcd7): undefined reference to `vaRenderPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:208:(.text+0xcf4): undefined reference to `vaEndPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:210:(.text+0xd02): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:184:(.text+0xd83): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:228:(.text+0xdb1): undefined reference to `vaEndPicture'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:202:(.text+0xdd3): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:230:(.text+0xdfb): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:193:(.text+0xe23): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `ff_vaapi_common_frame_params':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:687:(.text+0xf05): undefined reference to `vaDestroyConfig'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `ff_vaapi_decode_uninit':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:744:(.text+0xf58): undefined reference to `vaDestroyContext'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:746:(.text+0xf66): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:752:(.text+0xfa0): undefined reference to `vaDestroyConfig'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:754:(.text+0xfae): undefined reference to `vaErrorStr'
/usr/bin/ld: libavcodec/libavcodec.a(vaapi_decode.o): in function `ff_vaapi_decode_init':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:715:(.text+0x1090): undefined reference to `vaCreateContext'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavcodec/vaapi_decode.c:722:(.text+0x10cb): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_drm.o): in function `drm_device_create':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_drm.c:61:(.text+0x792): undefined reference to `drmGetVersion'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_drm.c:74:(.text+0x7ca): undefined reference to `drmFreeVersion'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_map_to_drm_esh':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1370:(.text+0xaf): undefined reference to `vaExportSurfaceHandle'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1376:(.text+0xfb): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1359:(.text+0x12c): undefined reference to `vaSyncSurface'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1361:(.text+0x5ef): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_unmap_to_drm_abh':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1451:(.text+0x71a): undefined reference to `vaReleaseBufferHandle'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1459:(.text+0x72a): undefined reference to `vaDestroyImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1453:(.text+0x755): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1461:(.text+0x78b): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_map_frame':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:842:(.text+0x8f0): undefined reference to `vaSyncSurface'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:876:(.text+0x92c): undefined reference to `vaCreateImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:906:(.text+0x951): undefined reference to `vaMapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:909:(.text+0xa53): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:939:(.text+0xa8c): undefined reference to `vaUnmapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:941:(.text+0xa9d): undefined reference to `vaDestroyImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:886:(.text+0xaca): undefined reference to `vaGetImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:859:(.text+0xafd): undefined reference to `vaDeriveImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:844:(.text+0xb37): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:879:(.text+0xb65): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:889:(.text+0xb91): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:861:(.text+0xbdf): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_unmap_frame':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:774:(.text+0xc5f): undefined reference to `vaUnmapBuffer'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:791:(.text+0xc7d): undefined reference to `vaDestroyImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:776:(.text+0xca6): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:793:(.text+0xcd3): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:782:(.text+0xd2e): undefined reference to `vaPutImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:786:(.text+0xd53): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_unmap_from_drm':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1088:(.text+0xeea): undefined reference to `vaDestroySurfaces'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_buffer_free':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:501:(.text+0xf45): undefined reference to `vaDestroySurfaces'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:503:(.text+0xf6d): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_frames_init':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:672:(.text+0x127b): undefined reference to `vaDeriveImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:683:(.text+0x12ba): undefined reference to `vaDestroyImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:685:(.text+0x139b): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_pool_alloc':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:522:(.text+0x1692): undefined reference to `vaCreateSurfaces'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:527:(.text+0x1724): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:537:(.text+0x175d): undefined reference to `vaDestroySurfaces'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_frames_get_constraints':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:249:(.text+0x18f3): undefined reference to `vaQuerySurfaceAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:264:(.text+0x1931): undefined reference to `vaQuerySurfaceAttributes'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:252:(.text+0x1adf): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:267:(.text+0x1b15): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_device_init':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:406:(.text+0x1b4d): undefined reference to `vaMaxNumImageFormats'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:416:(.text+0x1b84): undefined reference to `vaQueryImageFormats'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:443:(.text+0x1ceb): undefined reference to `vaQueryVendorString'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_device_free':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1639:(.text+0x1e8d): undefined reference to `vaTerminate'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_device_connect':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1676:(.text+0x1f10): undefined reference to `vaSetErrorCallback'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1677:(.text+0x1f22): undefined reference to `vaSetInfoCallback'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1682:(.text+0x1f36): undefined reference to `vaInitialize'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1684:(.text+0x1f83): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_device_derive':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1988:(.text+0x1fdc): undefined reference to `drmGetNodeTypeFromFd'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:2044:(.text+0x2025): undefined reference to `vaGetDisplayDRM'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1998:(.text+0x2053): undefined reference to `drmGetRenderDeviceNameFromFd'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_device_create':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1846:(.text+0x2221): undefined reference to `vaGetDisplayDRM'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1953:(.text+0x2254): undefined reference to `vaSetDriverName'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1864:(.text+0x22c7): undefined reference to `vaGetDisplay'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1776:(.text+0x2413): undefined reference to `drmGetVersion'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1798:(.text+0x2473): undefined reference to `drmFreeVersion'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1776:(.text+0x25a3): undefined reference to `drmGetVersion'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1811:(.text+0x25e0): undefined reference to `drmGetDevice'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1833:(.text+0x2667): undefined reference to `drmFreeDevice'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1789:(.text+0x26bc): undefined reference to `drmFreeVersion'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1955:(.text+0x2770): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1957:(.text+0x2798): undefined reference to `vaTerminate'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1804:(.text+0x27f4): undefined reference to `drmFreeVersion'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1824:(.text+0x281e): undefined reference to `drmFreeDevice'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1776:(.text+0x28ee): undefined reference to `drmGetVersion'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1836:(.text+0x291e): undefined reference to `drmFreeVersion'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1804:(.text+0x29c8): undefined reference to `drmFreeVersion'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_map_to_drm_abh':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1486:(.text+0x2b30): undefined reference to `vaDeriveImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1583:(.text+0x2c24): undefined reference to `vaDestroyImage'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1546:(.text+0x2d3a): undefined reference to `vaAcquireBufferHandle'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1489:(.text+0x2e88): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1549:(.text+0x2eb5): undefined reference to `vaErrorStr'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1581:(.text+0x2f13): undefined reference to `vaReleaseBufferHandle'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vaapi.o): in function `vaapi_map_from_drm':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1270:(.text+0x32df): undefined reference to `vaCreateSurfaces'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1219:(.text+0x3869): undefined reference to `vaCreateSurfaces'
/usr/bin/ld: /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vaapi.c:1307:(.text+0x3a2b): undefined reference to `vaErrorStr'
/usr/bin/ld: libavutil/libavutil.a(hwcontext_vdpau.o): in function `vdpau_device_create':
/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavutil/hwcontext_vdpau.c:494:(.text+0x759): undefined reference to `vdp_device_create_x11'
clang: error: linker command failed with exit code 1 (use -v to see invocation)

```

Let's take a look at how oss-fuzz compiles the project: https://github.com/google/oss-fuzz/blob/3416b4bff87c5b6363738ce2b2524e04c687119f/projects/ffmpeg/build.sh

```

./configure \
        --cc=$CC --cxx=$CXX --ld="$CXX $CXXFLAGS -std=c++11" \
        --extra-cflags="-I$FFMPEG_DEPS_PATH/include" \
        --extra-ldflags="-L$FFMPEG_DEPS_PATH/lib" \
        --prefix="$FFMPEG_DEPS_PATH" \
        --pkg-config-flags="--static" \
        --enable-ossfuzz \
        --libfuzzer=$LIB_FUZZING_ENGINE \
        --optflags=-O1 \
        --enable-gpl \
        --enable-nonfree \
        --enable-libass \
        --enable-libfdk-aac \
        --enable-libfreetype \
        --enable-libopus \
        --enable-libtheora \
        --enable-libvorbis \
        --enable-libvpx \
        --enable-libxml2 \
        --enable-nonfree \
        --disable-libdrm \
        --disable-muxers \
        --disable-protocols \
        --disable-demuxer=rtp,rtsp,sdp \
        --disable-devices \
        --disable-shared \
        --disable-doc \
        --disable-programs \
        $FFMPEG_BUILD_ARGS
make clean
make -j$(nproc) install

```

Let's add a couple of these to our build script...

Ok, so this build script seems to work:

```

FLAGS="-fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp -g" CC="clang $FLAGS" CXX="clang++ $FLAGS" LD="clang" ./configure  --disable-x86asm --pkg-config-flags="--static" --optflags=-O3 --enable-gpl --enable-nonfree --enable-libass --enable-libfdk-aac --enable-libfreetype --enable-libopus --enable-libtheora --enable-libvorbis --enable-libvpx --enable-libxml2 --enable-nonfree --disable-libdrm --disable-muxers --disable-protocols --disable-demuxer=rtp,rtsp,sdp --disable-devices --disable-shared --disable-doc --disable-programs
make clean && make -j$(nproc) # Build

```

and I had to modify the generated Makefile to include the graph fuzzer.

## Fixing bugs in our fuzzer.

The fuzzer has a couple of bugs. First of all the parsers expect the string to end in a null byte so we need to add that probably.

Here is my current source code:

```

/*
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/* Targeted fuzzer that targets the graphs.
  INSTRUCTIONS:

  * Get the very fresh clang, e.g. see http://libfuzzer.info#versions
  * Get and build libFuzzer:
     svn co http://llvm.org/svn/llvm-project/llvm/trunk/lib/Fuzzer
     ./Fuzzer/build.sh
  * build ffmpeg for fuzzing:
    FLAGS="-fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp -g" CC="clang $FLAGS" CXX="clang++ $FLAGS" ./configure  --disable-x86asm
    make clean && make -j
  * build the fuzz target.
    Choose the value of FFMPEG_CODEC (e.g. AV_CODEC_ID_DVD_SUBTITLE) and
    choose one of FUZZ_FFMPEG_VIDEO, FUZZ_FFMPEG_AUDIO, FUZZ_FFMPEG_SUBTITLE.
    clang -fsanitize=address -fsanitize-coverage=trace-pc-guard,trace-cmp tools/target_dec_fuzzer.c -o target_dec_fuzzer -I.   -DFFMPEG_CODEC=AV_CODEC_ID_MPEG1VIDEO -DFUZZ_FFMPEG_VIDEO ../../libfuzzer/libFuzzer.a   -Llibavcodec -Llibavdevice -Llibavfilter -Llibavformat -Llibavutil -Llibpostproc -Llibswscale -Llibswresample -Wl,--as-needed -Wl,-z,noexecstack -Wl,--warn-common -Wl,-rpath-link=:libpostproc:libswresample:libswscale:libavfilter:libavdevice:libavformat:libavcodec:libavutil -lavdevice -lavfilter -lavformat -lavcodec -lswresample -lswscale -lavutil -ldl -lxcb -lxcb-shm -lxcb -lxcb-xfixes  -lxcb -lxcb-shape -lxcb -lX11 -lasound -lm -lbz2 -lz -pthread
  * create a corpus directory and put some samples there (empty dir is ok too):
    mkdir CORPUS && cp some-files CORPUS

  * Run fuzzing:
    ./target_dec_fuzzer -max_len=100000 CORPUS

   More info:
   http://libfuzzer.info
   http://tutorial.libfuzzer.info
   https://github.com/google/oss-fuzz
   http://lcamtuf.coredump.cx/afl/
   https://security.googleblog.com/2016/08/guided-in-process-fuzzing-of-chrome.html
*/

// These next includes are taken from tools/uncoded_frame.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libavutil/avassert.h"
#include "libavutil/mem.h"
#include "libavdevice/avdevice.h"
#include "libavfilter/avfilter.h"
#include "libavfilter/buffersink.h"
#include "libavformat/avformat.h"
#include "libavcodec/codec_id.h"


int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // This fuzzer is based on the source found in tools/uncoded_frame.c
    int ret;
    if (size < 3) { // Skip empty or nonsensical short inputs.
        return 0;
    }
    // Now check for newline and space which are banned characters.
    //  Based on https://stackoverflow.com/a/9188556  thanks to stackoverflow user https://stackoverflow.com/users/65863/remy-lebeau

    //unsigned char buffer[1500];
    //bool allZeros = true;
    for (int i = 0; i < size; ++i)
    {
        if (data[i] == 0x0a || data[i] == 0x20) // For newline or space character
        {
            //allZeros = false;
            //break;
            return 0;
        }
    }
    // Now add a null byte at the end.
    data[size-1] = 0x00; // Add null byte at the end.
    AVFilterGraph *in_graph = NULL;
    if (!(in_graph = avfilter_graph_alloc())) { // If allocation fails, just bail out here early.
        return 0;
    }
    ret = avfilter_graph_parse_ptr(in_graph, data, NULL, NULL, NULL);
    // Now free the graph object to avoid memory leaks...
    avfilter_graph_free(&in_graph); // This is a bit weird that this expects a pointer but idk....
    return 0;
}


```

The resulting binary is over 100mb in size which seems quite large but idk... I mean it makes sense because we statically link everything...

```

enabled ossfuzz && ! echo $CFLAGS | grep -q -- "-fsanitize="  && ! echo $CFLAGS | grep -q -- "-fcoverage-mapping" &&{
    add_cflags  -fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp -fno-omit-frame-pointer
    add_ldflags -fsanitize=address,undefined -fsanitize-coverage=trace-pc-guard,trace-cmp

```

I had to add the ` --toolchain=clang-asan ` flag to the thing to make it compile correctly....

After like half an hour of compiling I finally had the working binary with coverage and shit and look at that.

```
-fsanitize-coverage=trace-pc-guard is no longer supported by libFuzzer.
```

fuck!!!!

We need to remove that shit out of everywhere and then try compiling again......

Also sidenote: Taking a look at parsers.c in the ffmpeg source code there appears to be plenty of parsers which can be fuzzed individually. The fuzzers which exist seem to fuzz every format at the same exact time. I think this is bad practice since ideally you would add a fuzzer for each one of them and fuzz each format on their own.

## Improving fuzzer with dictionary

Ok, so let's generate a filter graph string. There is quite a lot of documentation on filter graphs and stuff: https://ffmpeg.org/ffmpeg-filters.html

Let's try to generate a fuzzing dictionary based on that. Let's try to generate an automatic script which just grabs the stuff from the webpage.

Looking at the webpage source, the interesting strings are encompassed in "var" and "samp" tags in the html, so we can maybe just do something like this:

Here is a botched example:

```


# This script basically scrapes the web page for samp var and class="example" strings...


def fix_string(input_string: str) -> str:
	return input_string.replace("&quot;", "\"")

def process_lines(lines):

	output_strings = [] # All of the strings in the resulting dictionary.

	for line in lines:
		if line[-1] == "\n":
			line = line[:-1] # Cut out newline.
		# Now check for the shit...
		if "class=\"example\">" in line:
			line = line[line.index("class=\"example\">")+len("class=\"example\">"):]
			if len(line) < 2:
				continue
			# print("Here is the line: "+str(line))
			# Now check if it is just a segment or an actual command...
			if " " in line and "ffmpeg " in line:
				# Get the variables which have the "=" character in them
				stuff = line.split(" ")
				stuff = list(filter(lambda x: "=" in x, stuff))
				assert isinstance(stuff, list)
				assert all([isinstance(x, str) for x in stuff])
				# Replace the shit
				output_strings += stuff

	# Fixup the strings for example "&quot;" should be a double quote etc etc..

	output_strings = [fix_string(x) for x in output_strings]

	print("output shit: ")
	print("\n".join(output_strings))
def autodict():
	fh = open("ffmpeg-filters.html", "r")
	lines = fh.readlines()
	fh.close()
	process_lines(lines)
	return

if __name__=="__main__":
	autodict()
	exit(0)


```

and it seems to work decently. Here is the output:

```

crop=iw:ih/2:0:0,
overlay=0:H/2"
scale=640:360
drawtext=/text=/tmp/some_text
acrossfade=d=10:c1=exp:c2=exp
acrossfade=d=10:o=0:c1=exp:c2=exp
'acrossover=split=1500[LOW][HIGH]'
'acrossover=split=1500:order=8th[LOW][HIGH]'
'acrossover=split=1500
8000:order=8th[LOW][MID][HIGH]'
amerge=inputs=6"
amix=inputs=3:duration=first:dropout_transition=3
amix=inputs=2:duration=longest:dropout_transition=0:weights="1
0.25":normalize=0
atrim=60:120
atrim=end_sample=1000
channelsplit,axcorrelate=size=1024:algo=fast
'channelmap=map=DL-FL|DR-FR'
'channelmap=1|2|0|5|3|4:5.1'
'channelsplit=channel_layout=5.1:channels=LFE[LFE]'
"amovie=minp.wav[hrirs];[0:a][hrirs]headphone=map=FL|FR|FC|LFE|BL|BR|SL|SR:hrir=multich"
join=inputs=3
"[1:a]asplit=2[sc][mix];[0:a][sc]sidechaincompress[compr];[compr][mix]amerge"
silencedetect=noise=0.0001
flite=text='So
am':voice=slt
chromakey=green
color=c=black:s=1280x720
"[1:v]chromakey=0x70de77:0.1:0.2[ckout];[0:v][ckout]overlay[out]"
cuda=cuda
colorkey=green
"[1:v]colorkey=0x3BBD1E:0.3:0.2[ckout];[0:v][ckout]overlay[out]"
nullsrc=s=100x100,coreimage=filter=CIQRCodeGenerator@inputMessage=https\\\\\://FFmpeg.org/@inputCorrectionLevel=H
find_rect=newref.pgm,cover_rect=cover.jpg:mode=cover
cropdetect,metadata=mode=print
mestimate,cropdetect=mode=mvedges,metadata=mode=print
cropdetect=mode=mvedges,metadata=mode=print
curves=cross_process:plot=/tmp/curves.plt
nullsrc=s=hd720,lutrgb=128:128:128
nullsrc=s=hd720,geq='r=128+30*sin(2*PI*X/400+T):g=128+30*sin(2*PI*X/400+T):b=128+30*sin(2*PI*X/400+T)'
nullsrc=hd720,geq='r=128+80*(sin(sqrt((X-W/2)*(X-W/2)+(Y-H/2)*(Y-H/2))/220*2*PI+T)):g=128+80*(sin(sqrt((X-W/2)*(X-W/2)+(Y-H/2)*(Y-H/2))/220*2*PI+T)):b=128+80*(sin(sqrt((X-W/2)*(X-W/2)+(Y-H/2)*(Y-H/2))/220*2*PI+T))'
format=rgb24,dnn_processing=dnn_backend=tensorflow:model=can.pb:input=x:output=y
format=yuv420p,scale=w=iw*2:h=ih*2,dnn_processing=dnn_backend=tensorflow:model=srcnn.pb:input=x:output=y
format=yuv420p,dnn_processing=dnn_backend=tensorflow:model=espcn.pb:input=x:output=y:backend_configs=sess_config=0x10022805320e09cdccccccccccec3f20012a01303801
'extractplanes=y+u+v[y][u][v]'
"fieldorder=bff"
find_rect=newref.pgm,cover_rect=cover.jpg:mode=cover
zscale=transfer=linear,grayworld,zscale=transfer=bt709,format=yuv420p
guided=guidance=on
href="#haldclutsrc">haldclutsrc</a>=8
"hue=H=2*PI*t:s=sin(2*PI*t)+1,
curves=cross_process"
href="#haldclutsrc">haldclutsrc</a>=8
idet,metadata=mode=print
lensfun=make=Canon:model="Canon
100D":lens_model="Canon
STM":focal_length=18:aperture=8
lensfun=make=Canon:model="Canon
100D":lens_model="Canon
STM":focal_length=18:aperture=8:enable='lte(t\,5)'
libplacebo=upscaler=none:downscaler=none:peak_detect=false
libplacebo=apply_filmgrain=true
libvmaf=log_path=output.xml
libvmaf='model=version=vmaf_v0.6.1\\:name=vmaf|version=vmaf_v0.6.1neg\\:name=vmaf_neg'
libvmaf='feature=name=psnr|name=ciede'
"[0:v]settb=AVTB,setpts=PTS-STARTPTS[main];[1:v]settb=AVTB,setpts=PTS-STARTPTS[ref];[main][ref]libvmaf=log_fmt=json:log_path=output.json"
'overlay=10:main_h-overlay_h-10'
'overlay=x=10:y=H-h-10,overlay=x=W-w-10:y=H-h-10'
"[0:v]settb=AVTB,setpts=PTS-STARTPTS[main];[1:v]settb=AVTB,setpts=PTS-STARTPTS[ref];[main][ref]psnr"
'readvitc,drawtext=fontfile=FreeMono.ttf:text=%{metadata\\:lavfi.readvitc.tc_str\\:--\\\\\\:--\\\\\\:--\\\\\\:--}:x=(w-tw)/2:y=400-ascent'
"shuffleframes=0
"shuffleframes=9
shuffleplanes=0:2:1:3
signature=filename=signature.bin
signature=nb_inputs=2:detectmode=full:format=xml:filename=signature%d.xml"
siti=print_summary=1
"[0:v]settb=AVTB,setpts=PTS-STARTPTS[main];[1:v]settb=AVTB,setpts=PTS-STARTPTS[ref];[main][ref]ssim"
color=gray
color=black
color=white
color=gray
color=white
color=black
color=gray
color=gray
color=gray
color=white
color=gray
color=white
thumbnail,scale=300:200
'scale=128:72,tile=8x8'
zscale=transfer=linear,tonemap=clip,zscale=transfer=bt709,format=yuv420p
trim=60:120
trim=duration=1
untile=1x25
v360=e:c3x2:cubic:out_pad=0.01
v360=eac:flat:yaw=180
vidstabdetect=shakiness=5:show=1
vidstabtransform,unsharp=5:5:0.8:3:3:0.4
xfade=transition=fade:duration=2:offset=5
coreimagesrc=s=100x100:filter=CIQRCodeGenerator@inputMessage=https\\\\\://FFmpeg.org/@inputCorrectionLevel=H
ddagrab=output_idx=1:framerate=60,hwdownload,format=bgra
aphasemeter=video=0:phasing=1:duration=1:tolerance=0.001
select='gt(scene\,0.4)',scale=160:120,tile
select=concatdec_select
aselect=concatdec_select
showspectrumpic=s=1024x1024
showwavespic=split_channels=1:s=1024x800
showspectrum=mode=separate:scale=log:overlap=0.875:color=channel:slide=fullframe:data=magnitude
asplit=5

```

which seems decent enough. Let's program the other cases too.

```



```


## Fixing the fuzzer

Actually before we do that let's address a crash which the fuzzer found.

```

oof@elskun-lppri:~/ffmpegfuzzerthing/myfork/FFmpeg/tools/fuzzingcampaign$ ./target_graph_fuzzer final.bin
INFO: Running with entropic power schedule (0xFF, 100).
INFO: Seed: 840731882
INFO: Loaded 1 modules   (1514265 inline 8-bit counters): 1514265 [0x55786e892c38, 0x55786ea04751),
INFO: Loaded 1 PC tables (1514265 PCs): 1514265 [0x55786ea04758,0x55787011f8e8),
./target_graph_fuzzer: Running 1 inputs 1 time(s) each.
Running: final.bin
[Parsed_abuffersink_0 @ 0x511000000180] The "sample_fmts" option is deprecated: set the supported sample formats
[Parsed_abuffersink_0 @ 0x511000000180] The "sample_rates" option is deprecated: set the supported sample rates
[Parsed_abuffersink_0 @ 0x511000000180] The "ch_layouts" option is deprecated: set a '|'-separated list of supported channel layouts
libavfilter/buffersink.c:208:25: runtime error: applying zero offset to null pointer
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior libavfilter/buffersink.c:208:25
libavfilter/buffersink.c:208:24: runtime error: null pointer passed as argument 1, which is declared to never be null
/usr/include/string.h:61:62: note: nonnull attribute specified here
SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior libavfilter/buffersink.c:208:24
AddressSanitizer:DEADLYSIGNAL
=================================================================
==422428==ERROR: AddressSanitizer: SEGV on unknown address 0x000000000000 (pc 0x7f726ced6500 bp 0x7ffdfb649270 sp 0x7ffdfb648a38 T0)
==422428==The signal is caused by a WRITE memory access.
==422428==Hint: address points to the zero page.
    #0 0x7f726ced6500  (/lib/x86_64-linux-gnu/libc.so.6+0x189500) (BuildId: 6d64b17fbac799e68da7ebd9985ddf9b5cb375e6)
    #1 0x55786903e29e in __asan_memset (/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/tools/fuzzingcampaign/target_graph_fuzzer+0x41ee29e) (BuildId: c1e736a748ca18c0ca919e9db2eaf1561ad2f67a)
    #2 0x557868d6c07d in common_init /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/buffersink.c:208:17
    #3 0x55786925ba90 in avfilter_init_dict /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/avfilter.c:939:15
    #4 0x5578690df2ab in avfilter_graph_segment_init /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/graphparser.c:634:19
    #5 0x5578690e3abc in avfilter_graph_parse_ptr /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/libavfilter/graphparser.c:948:11
    #6 0x55786907ebae in LLVMFuzzerTestOneInput /home/oof/ffmpegfuzzerthing/myfork/FFmpeg/tools/target_graph_fuzzer.c:104:11
    #7 0x557868f8c174 in fuzzer::Fuzzer::ExecuteCallback(unsigned char const*, unsigned long) (/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/tools/fuzzingcampaign/target_graph_fuzzer+0x413c174) (BuildId: c1e736a748ca18c0ca919e9db2eaf1561ad2f67a)
    #8 0x557868f752a6 in fuzzer::RunOneTest(fuzzer::Fuzzer*, char const*, unsigned long) (/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/tools/fuzzingcampaign/target_graph_fuzzer+0x41252a6) (BuildId: c1e736a748ca18c0ca919e9db2eaf1561ad2f67a)
    #9 0x557868f7ad5a in fuzzer::FuzzerDriver(int*, char***, int (*)(unsigned char const*, unsigned long)) (/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/tools/fuzzingcampaign/target_graph_fuzzer+0x412ad5a) (BuildId: c1e736a748ca18c0ca919e9db2eaf1561ad2f67a)
    #10 0x557868fa5516 in main (/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/tools/fuzzingcampaign/target_graph_fuzzer+0x4155516) (BuildId: c1e736a748ca18c0ca919e9db2eaf1561ad2f67a)
    #11 0x7f726cd771c9  (/lib/x86_64-linux-gnu/libc.so.6+0x2a1c9) (BuildId: 6d64b17fbac799e68da7ebd9985ddf9b5cb375e6)
    #12 0x7f726cd7728a in __libc_start_main (/lib/x86_64-linux-gnu/libc.so.6+0x2a28a) (BuildId: 6d64b17fbac799e68da7ebd9985ddf9b5cb375e6)
    #13 0x557868f6fe74 in _start (/home/oof/ffmpegfuzzerthing/myfork/FFmpeg/tools/fuzzingcampaign/target_graph_fuzzer+0x411fe74) (BuildId: c1e736a748ca18c0ca919e9db2eaf1561ad2f67a)

AddressSanitizer can not provide additional info.
SUMMARY: AddressSanitizer: SEGV (/lib/x86_64-linux-gnu/libc.so.6+0x189500) (BuildId: 6d64b17fbac799e68da7ebd9985ddf9b5cb375e6)
==422428==ABORTING

```















































