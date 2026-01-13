
# Improving a google oss-fuzz harness.

Ok, so I was scrolling a hacking discord a bit and I noticed this:

![Google pays quite a lot](pictures/ossfuzz.png)

I decided to try my hand in improving some of the harnesses in oss-fuzz.

## Improving the fuzzing harness for tremor:

Ok, so after going through a couple of targets, I found one which seems quite outdated and which doesn't have a very impressive fuzzing harness: https://gitlab.xiph.org/xiph/tremor

Here is the current harness: (As of 24th of February 2024)

{% raw %}
```
/* Copyright (C) 2019 Mozilla Foundation.
   File: decode_fuzzer.cc
 
   Redistribution and use in source and binary forms, with or without
   modification, are permitted provided that the following conditions
   are met:
 
   - Redistributions of source code must retain the above copyright
   notice, this list of conditions and the following disclaimer.
 
   - Redistributions in binary form must reproduce the above copyright
   notice, this list of conditions and the following disclaimer in the
   documentation and/or other materials provided with the distribution.
 
   - Neither the name of the Xiph.org Foundation nor the names of its
   contributors may be used to endorse or promote products derived from
   this software without specific prior written permission.
 
   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
   ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
   A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE FOUNDATION OR
   CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
   EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
   PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
   PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
   LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
   NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/
/* This based on decode_fuzzer.cc used with Vorbis.
   https://git.xiph.org/?p=vorbis.git;a=blob;f=contrib/oss-fuzz/decode_fuzzer.cc;hb=HEAD
*/

#include <stdio.h>
#include <string.h>
#include <cstdint>
#include "ivorbisfile.h"

#define INPUT_LIMIT 16384

struct vorbis_data {
  const uint8_t *current;
  const uint8_t *data;
  size_t size;
};

size_t read_func(void *ptr, size_t size1, size_t size2, void *datasource) {
  vorbis_data* vd = (vorbis_data *)(datasource);
  size_t len = size1 * size2;
  if (vd->current + len > vd->data + vd->size) {
      len = vd->data + vd->size - vd->current;
  }
  memcpy(ptr, vd->current, len);
  vd->current += len;
  return len;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
  ov_callbacks memory_callbacks = {0};
  memory_callbacks.read_func = read_func;
  vorbis_data data_st;
  data_st.size = Size > INPUT_LIMIT ? INPUT_LIMIT : Size;
  data_st.current = Data;
  data_st.data = Data;
  OggVorbis_File vf;
  int result = ov_open_callbacks(&data_st, &vf, NULL, 0, memory_callbacks);
  if (result < 0) {
    return 0;
  }
  int current_section = 0;
  char pcm[4096];
  long read_result;
  while (true) {
    read_result = ov_read(&vf, pcm, sizeof(pcm), &current_section);
    if (read_result <= 0 && read_result != OV_HOLE) {
      break;
    }
  }
  ov_clear(&vf);
  return 0;
}

```
{% endraw %}

which is quite a decent harness.

After the painstaking process of creating a coverage report, here it is:

![](pictures/tremor_cov.png)

as we can see, we only have around 62 percent of the functions covered. There is quite a lot of space for improvement.

One thing which we can add is we can add coverage for the ov_comment function. Another thing which we can do is we can add support for the fuzzing of seekable files. This is because there are a lot of functions in there which need a seekable file in order to work. For example this:

{% raw %}
```
     927          56 : static int _ov_open2(OggVorbis_File *vf){
     928          56 :   if(vf->ready_state != PARTOPEN) return OV_EINVAL;
     929          56 :   vf->ready_state=OPENED;
     930          56 :   if(vf->seekable){
     931           0 :     int ret=_open_seekable2(vf);
     932           0 :     if(ret){
     933           0 :       vf->datasource=NULL;
     934           0 :       ov_clear(vf);
     935             :     }
     936           0 :     return(ret);
     937             :   }else
     938          56 :     vf->ready_state=STREAMSET;
     939             : 
     940          56 :   return 0;
     941             : }
```
{% endraw %}

where the _open_seekable2 function only gets called if the file is seekable. and stdin is not seekable, therefore this is never called. So maybe we should add a method which takes in data from stdin, then writes it to a file and then reads that file. This causes the seekable condition to be true and therefore causes more coverage.

## Looking for another target.

Ok, so that library didn't really yield that good of results, so let's try to find a more better target.

Luckily for us, we can sort by language in oss-fuzz, because there is a yaml file which has a tag called language. Here we can see that if we can add a sanitizer and then find two bugs with it, then we are eligible for a payout: https://bughunters.google.com/about/rules/5097259337383936/oss-fuzz-reward-program-rules . If there isn't a sanitizer tag present, then the default sanitizers of address and undefined are used. (No MSAN, because it can cause problems) according to this: https://github.com/google/oss-fuzz/blob/master/docs/getting-started/new_project_guide.md#sanitizers-optional-sanitizers

Ok, so there aren't any interesting looking projects which do not use some of the sanitizers. That sucks. Thanks for reading anyway!















