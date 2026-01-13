# Fuzzing SVG files in blink

Ok, so I am getting these errors here:

{% raw %}
```

```
{% endraw %}

And I think this is because we need to include the `"//third_party/blink/renderer/controller:blink_bindings_test_sources",` file in our `gn` script. This is because we need to include the file which includes the `v8_binding_for_testing.h` file and that seems to be the `"//third_party/blink/renderer/controller:blink_bindings_test_sources",` thing. Just to make sure, let's just include all the shit to be sure...

{% raw %}
```
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer/core$ grep -r "V8TestingScope" | grep "class"
^C^[[A^C^C^C^C^C^C^C^C^C^C^Chtml/custom/custom_element_test_helpers.h:class CustomElementTestingScope : public V8TestingScope {
fetch/fetch_later_test_util.h:class FetchLaterTestingScope : public V8TestingScope {
streams/test_utils.h:class V8TestingScope;
^C
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer/core$ ^C
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer/core$ grep -r "V8TestingScope" * | grep "class"
fetch/fetch_later_test_util.h:class FetchLaterTestingScope : public V8TestingScope {
html/custom/custom_element_test_helpers.h:class CustomElementTestingScope : public V8TestingScope {
streams/test_utils.h:class V8TestingScope;
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer/core$ cd ..
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer$ grep -r "V8TestingScope" * | grep "class"
bindings/core/v8/world_safe_v8_reference_test.cc:class IsolateOnlyV8TestingScope {
bindings/core/v8/v8_binding_for_testing.h:class V8TestingScope {
core/html/custom/custom_element_test_helpers.h:class CustomElementTestingScope : public V8TestingScope {
core/fetch/fetch_later_test_util.h:class FetchLaterTestingScope : public V8TestingScope {
core/streams/test_utils.h:class V8TestingScope;
^C
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer$ grep -r ^C
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer$ grep -r blink_core_tests_css *
core/BUILD.gn:  sources += rebase_path(blink_core_tests_css, "", "css")
core/css/build.gni:blink_core_tests_css = [
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer$ subl core/BUILD.gn
oof@oof-h8-1440eo:~/chromiumstuff/source/src/third_party/blink/renderer$ grep -r "v8_binding_for_testing.h" *
bindings/bindings.gni:          "core/v8/v8_binding_for_testing.h",
bindings/modules/v8/v8_element_test.cc:#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"
bindings/modules/v8/v8_binding_for_modules_test.cc:#include "third_party/blink/renderer/bindings/core/v8/v8_binding_for_testing.h"

```
{% endraw %}

Add the `"//third_party/blink/renderer/controller:blink_bindings_test_sources",` shit maybe???

Here is the shit:

{% raw %}
```


source_set("unit_tests") {
  testonly = true

  # If you create a new subdirectory 'foo' that contains unit tests, list them in
  # 'foo/build.gni' to define blink_core_tests_foo, and add any dependencies in
  # the deps section below.
  sources = rebase_path(blink_core_tests_accessibility, "", "accessibility")
  sources += rebase_path(blink_core_tests_animation, "", "animation")
  sources += rebase_path(blink_core_tests_annotation, "", "annotation")
  sources += rebase_path(blink_core_tests_canvas_interventions,
                         "",
                         "canvas_interventions")
  sources += rebase_path(blink_core_tests_clipboard, "", "clipboard")
  sources +=
      rebase_path(blink_core_tests_content_capture, "", "content_capture")
  sources += rebase_path(blink_core_tests_css, "", "css")
  sources += rebase_path(blink_core_tests_display_lock, "", "display_lock")
  sources +=
      rebase_path(blink_core_tests_view_transition, "", "view_transition")
  sources += rebase_path(blink_core_tests_dom, "", "dom")
  sources += rebase_path(blink_core_tests_editing, "", "editing")
  sources += rebase_path(blink_core_tests_events, "", "events")
  sources +=
      rebase_path(blink_core_tests_execution_context, "", "execution_context")
  sources += rebase_path(blink_core_tests_exported, "", "exported")
  sources += rebase_path(blink_core_tests_fetch, "", "fetch")
  sources += rebase_path(blink_core_tests_fileapi, "", "fileapi")
  sources +=
      rebase_path(blink_core_tests_fragment_directive, "", "fragment_directive")
  sources += rebase_path(blink_core_tests_frame, "", "frame")
  sources += rebase_path(blink_core_tests_fullscreen, "", "fullscreen")
  sources += rebase_path(blink_core_tests_geometry, "", "geometry")
  sources += rebase_path(blink_core_tests_highlight, "", "highlight")
  sources += rebase_path(blink_core_tests_html, "", "html")
  sources += rebase_path(blink_core_tests_imagebitmap, "", "imagebitmap")
  sources += rebase_path(blink_core_tests_input, "", "input")
  sources += rebase_path(blink_core_tests_inspector, "", "inspector")
  sources += rebase_path(blink_core_tests_intersection_observer,
                         "",
                         "intersection_observer")
  sources += rebase_path(blink_core_tests_layout, "", "layout")
  sources += rebase_path(blink_core_tests_lcp_critical_path_predictor,
                         "",
                         "lcp_critical_path_predictor")
  sources += rebase_path(blink_core_tests_loader, "", "loader")
  sources += rebase_path(blink_core_tests_mathml, "", "mathml")
  sources += rebase_path(blink_core_tests_messaging, "", "messaging")
  sources += rebase_path(blink_core_tests_mobile_metrics, "", "mobile_metrics")
  sources += rebase_path(blink_core_tests_navigation_api, "", "navigation_api")
  sources += rebase_path(blink_core_tests_origin_trials, "", "origin_trials")
  sources += rebase_path(blink_core_tests_page, "", "page")
  sources += rebase_path(blink_core_tests_paint, "", "paint")
  sources +=
      rebase_path(blink_core_tests_permissions_policy, "", "permissions_policy")
  sources +=
      rebase_path(blink_core_tests_resize_observer, "", "resize_observer")
  sources += rebase_path(blink_core_tests_sanitizer, "", "sanitizer")
  sources += rebase_path(blink_core_tests_scheduler, "", "scheduler")
  sources += rebase_path(blink_core_tests_scheduler_integration_tests,
                         "",
                         "scheduler_integration_tests")
  sources += rebase_path(blink_core_tests_script, "", "script")
  sources += rebase_path(blink_core_tests_scroll, "", "scroll")
  sources +=
      rebase_path(blink_core_tests_speculation_rules, "", "speculation_rules")
  sources += rebase_path(blink_core_tests_streams, "", "streams")
  sources += rebase_path(blink_core_tests_style, "", "style")
  sources += rebase_path(blink_core_tests_svg, "", "svg")
  sources += rebase_path(blink_core_tests_timing, "", "timing")
  sources += rebase_path(blink_core_tests_trustedtypes, "", "trustedtypes")
  sources += rebase_path(blink_core_tests_typed_arrays, "", "typed_arrays")
  sources += rebase_path(blink_core_tests_url, "", "url")
  sources += rebase_path(blink_core_tests_url_pattern, "", "url_pattern")
  sources += rebase_path(blink_core_tests_workers, "", "workers")
  sources += rebase_path(blink_core_tests_xml, "", "xml")
  sources += rebase_path(blink_core_tests_xmlhttprequest, "", "xmlhttprequest")

  configs += [
    ":blink_core_pch",
    "//third_party/blink/renderer:config",
    "//third_party/blink/renderer:inside_blink",
  ]

  deps = [
    ":core",
    ":element_locator_proto",
    ":unit_test_support",
    "//cc",
    "//components/autofill/core/common:features",
    "//components/page_load_metrics/browser:browser",
    "//components/paint_preview/common:common",
    "//components/shared_highlighting/core/common",
    "//components/shared_highlighting/core/common:data_driven_testing",
    "//components/subresource_filter/content/renderer",
    "//components/subresource_filter/core/common",
    "//components/subresource_filter/core/common:test_support",
    "//components/ukm:test_support",
    "//components/viz/test:test_support",
    "//content/test:test_support",
    "//gpu/command_buffer/client:raster",
    "//gpu/config",
    "//mojo/public/cpp/system",
    "//mojo/public/cpp/test_support:test_utils",
    "//services/metrics/public/cpp:ukm_builders",
    "//services/network:test_support",
    "//services/network/public/mojom:mojom_permissions_policy",
    "//skia",
    "//skia:skcms",
    "//testing/gmock",
    "//testing/gtest",
    "//third_party:freetype_harfbuzz",
    "//third_party/blink/common/privacy_budget:test_support",
    "//third_party/blink/public:buildflags",
    "//third_party/blink/public:test_headers",
    "//third_party/blink/public/common/privacy_budget:test_support",
    "//third_party/blink/public/strings:permission_element_generated_strings_grit",
    "//third_party/blink/public/strings:permission_element_strings_grit",
    "//third_party/blink/renderer/controller:blink_bindings_test_sources",
    "//third_party/blink/renderer/core",
    "//third_party/blink/renderer/core:testing",
    "//third_party/blink/renderer/core:unit_test_support",
    "//third_party/blink/renderer/core/sanitizer:unit_test_support",
    "//third_party/blink/renderer/platform:test_support",
    "//third_party/fuzztest",
    "//ui/accessibility:ax_base",
    "//ui/base/cursor",
    "//ui/base/cursor/mojom:cursor_type_blink",
    "//ui/base/dragdrop/mojom:mojom_blink",
    "//ui/base/mojom:ui_base_types_blink",
    "//ui/gfx:test_support",
  ]

```
{% endraw %}

I am just going to take `"//third_party/blink/renderer/controller:blink_bindings_test_sources",` and slap it into the build file and see what happens. I am not going to assume that this is immediately succesful, but let's see...

My current BUILD.gn looks like this:

{% raw %}
```
# Fuzzer for SVG document parsing
fuzzer_test("svg_document_fuzzer") {
  sources = [ "svg/svg_document_fuzzer.cc" ]
  deps = [
    ":core",
    "//third_party/blink/renderer/platform:platform",
    "//third_party/blink/renderer/controller:blink_bindings_test_sources",
    "../platform:blink_fuzzer_test_support",
  ]
  dict = "//third_party/blink/renderer/core/svg/svg.dict"
  seed_corpus = "//third_party/blink/renderer/core/svg/svg_document_corpus"
}

```
{% endraw %}

