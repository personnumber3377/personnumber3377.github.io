
# Fuzzing librsvg

look at: https://gitlab.gnome.org/GNOME/pango/-/issues/810




## Introduction

I previously programmed a DOS-style bug finder to find DOS style bugs in different kinds of software, and as it turns out, this tool is quite fun to use and I have already discovered a decent amount of bugs with it... this time I am going to use it against librsvg and see what I can do...

## Compiling

Ok, so compiling yielded some quite bad results for me, and I decided to actually open an issue on the project itself which explains the problems which I was facing: https://gitlab.gnome.org/GNOME/pango/-/issues/810 (that issue was opened by me) ...

I solved it by using this `Cargo.toml` in the `afl-fuzz/` directory:

```

[package]
name = "rsvg-afl-fuzz"
version = "0.0.1"
authors = ["Bastien Orivel <eijebong@bananium.fr>"]
edition = "2018"

[dependencies]
afl = "0.15.10"
cairo-rs = "0.20.0"
glib = "0.20.0"
gio = "0.20.0"
# librsvg = { path = "/home/oof/librsvg" }
librsvg = "2.59.0-beta.3"

[profile.release]
lto = true
debug = true

[profile.bench]
lto = true


```

and it seems to do fine...

## Gathering a bigger corpus.

Ok, so next up is to find a bigger corpus for fuzzing, if you look at the readme in the `afl-fuzz` directory: https://gitlab.gnome.org/GNOME/librsvg/-/blob/main/afl-fuzz/README.md?ref_type=heads , you can see that we need a better corpus...

Now, one quite a nice corpus is at https://github.com/strongcourage/fuzzing-corpus in the svg directory. That seems nice. Let's plagiar... erm... import it :D .

Next up, let's use a google dork to get filetypes with the `.svg` extension. You can take a look at my corpus here: https://github.com/personnumber3377/svg_fuzzing_corpus

## Grabbing the dictionary

Now, the fuzzing readme warns that afl can not use dictionaries larger than 128 bytes in size, but I haven't heard of that restriction anywhere? Maybe it was in older versions... Let's just grab some svg dictionary and see what happens...

The dictionary which comes with afl-fuzz looks like this:

```
# Keywords taken from
#  - https://developer.mozilla.org/en-US/docs/Web/SVG/Tutorial/Introduction
#  - https://css-tricks.com/svg-properties-and-css/

"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
"standalone="
"version="
"encoding="
"<?xml"
"?>"
"/>"
"<![CDATA["

# tags
"<svg"
"xmlns=\"http://www.w3.org/2000/svg\""
"<a"
"<animate"
"<animateMotion"
"<animateTransform"
"<circle"
"<clipPath"
"<color-profile"
"<defs"
"<desc"
"<discard"
"<ellipse"
"<feBlend"
"<feColorMatrix"
"<feComponentTransfer"
"<feComposite"
"<feConvolveMatrix"
"<feDiffuseLighting"
"<feDisplacementMap"
"<feDistantLight"
"<feDropShadow"
"<feFlood"
"<feFuncA"
"<feFuncB"
"<feFuncG"
"<feFuncR"
"<feGaussianBlur"
"<feImage"
"<feMerge"
"<feMergeNode"
"<feMorphology"
"<feOffset"
"<fePointLight"
"<feSpecularLighting"
"<feSpotLight"
"<feTile"
"<feTurbulence"
"<filter"
"<foreignObject"
"<g"
"<hatch"
"<hatchpath"
"<image"
"<line"
"<linearGradient"
"<marker"
"<mask"
"<mesh"
"<meshgradient"
"<meshpatch"
"<meshrow"
"<metadata"
"<mpath"
"<path"
"<pattern"
"<polygon"
"<polyline"
"<radialGradient"
"<rect"
"<rect"
"<script"
"<script>"
"<set"
"<solidcolor"
"<stop"
"<style"
"<svg"
"<switch"
"<symbol"
"<text"
"<textArea"
"<textPath"
"<title"
"<title>"
"<tspan"
"<unknown"
"<use"
"<view"


# attributes
"alignment-baseline"
"baseline-shift"
"class"
"color"
"cursor"
"cx"
"cy"
"direction"
"display"
"dominant-baseline"
"editable"
"fill"
"fill-opacity"
"font-family"
"font-size"
"font-size-adjust"
"font-stretch"
"font-style"
"font-variant"
"font-weight"
"glyph-orientation-horizontal"
"glyph-orientation-vertical"
"gradientUnits"
"height"
"kerning""
"letter-spacing"
"offset"
"overflow"
"patternContentUnits"
"pointer-events"
"points"
"rotate"
"rx"
"ry"
"spreadMethod"
"stop-color"
"stop-opacity"
"stroke"
"stroke-dasharray"
"stroke-linecap"
"stroke-linejoin"
"stroke-opacity"
"stroke-width"
"style"
"text-anchor"
"text-decoration"
"textlength"
"transform"
"unicode-bidi"
"visibility"
"width"
"word-spacing"
"writing-mode"
"x1"
"x2"
"y1"
"y2"

# attributes' values
"bounding-Box"
"repeat"
"display"
"transparent"
"orange"
"round"
"butt"
"userSpaceOnUse"
"objectBoundingBox"
"square"
"miter"
"bevel"
"translate("
"rotate("
"matrix("

```


I think I should program an autodictionary tool, which generates fuzzing dictionaries from the source code without having to manually look at it. That I think already exists for clang, but it would be nice to have it with other programming languages as well: https://github.com/AFLplusplus/AFLplusplus/blob/stable/instrumentation/README.lto.md#autodictionary-feature

For simplicity, I just ran `grep -r "\" =>"` on the source code, because the match operator is quite often used to match strings and this is the output:

```

property_macros.rs:///     "miter" => Miter,
property_macros.rs:///     "round" => Round,
property_macros.rs:///     "bevel" => Bevel,
properties.rs:        "color-interpolation-filters" => (PresentationAttr::Yes, color_interpolation_filters : ColorInterpolationFilters),
properties.rs:        "height" => (PresentationAttr::Yes, height: Height),
gradient.rs:            "pad" => SpreadMethod::Pad,
gradient.rs:            "reflect" => SpreadMethod::Reflect,
gradient.rs:            "repeat" => SpreadMethod::Repeat,
parsers.rs:///     "true" => true,
parsers.rs:///     "false" => false,
property_defs.rs:                            "baseline" => BaselineShift(Length::<Both>::new(0.0, LengthUnit::Percent)),
property_defs.rs:                            "sub" => BaselineShift(Length::<Both>::new(-0.2, LengthUnit::Percent)),
property_defs.rs:                            "super" => BaselineShift(Length::<Both>::new(0.4, LengthUnit::Percent)),
property_defs.rs:    "nonzero" => NonZero,
property_defs.rs:    "evenodd" => EvenOdd,
property_defs.rs:    "auto" => Auto,
property_defs.rs:    "linearRGB" => LinearRgb,
property_defs.rs:    "sRGB" => Srgb,
property_defs.rs:    "ltr" => Ltr,
property_defs.rs:    "rtl" => Rtl,
property_defs.rs:    "inline" => Inline,
property_defs.rs:    "block" => Block,
property_defs.rs:    "list-item" => ListItem,
property_defs.rs:    "run-in" => RunIn,
property_defs.rs:    "compact" => Compact,
property_defs.rs:    "marker" => Marker,
property_defs.rs:    "table" => Table,
property_defs.rs:    "inline-table" => InlineTable,
property_defs.rs:    "table-row-group" => TableRowGroup,
property_defs.rs:    "table-header-group" => TableHeaderGroup,
property_defs.rs:    "table-footer-group" => TableFooterGroup,
property_defs.rs:    "table-row" => TableRow,
property_defs.rs:    "table-column-group" => TableColumnGroup,
property_defs.rs:    "table-column" => TableColumn,
property_defs.rs:    "table-cell" => TableCell,
property_defs.rs:    "table-caption" => TableCaption,
property_defs.rs:    "none" => None,
property_defs.rs:    "nonzero" => NonZero,
property_defs.rs:    "evenodd" => EvenOdd,
property_defs.rs:    "normal" => Normal,
property_defs.rs:    "wider" => Wider,
property_defs.rs:    "narrower" => Narrower,
property_defs.rs:    "ultra-condensed" => UltraCondensed,
property_defs.rs:    "extra-condensed" => ExtraCondensed,
property_defs.rs:    "condensed" => Condensed,
property_defs.rs:    "semi-condensed" => SemiCondensed,
property_defs.rs:    "semi-expanded" => SemiExpanded,
property_defs.rs:    "expanded" => Expanded,
property_defs.rs:    "extra-expanded" => ExtraExpanded,
property_defs.rs:    "ultra-expanded" => UltraExpanded,
property_defs.rs:    "normal" => Normal,
property_defs.rs:    "italic" => Italic,
property_defs.rs:    "oblique" => Oblique,
property_defs.rs:    "normal" => Normal,
property_defs.rs:    "small-caps" => SmallCaps,
property_defs.rs:    "auto" => Auto,
property_defs.rs:    "smooth" => Smooth,
property_defs.rs:    "optimizeQuality" => OptimizeQuality,
property_defs.rs:    "high-quality" => HighQuality,
property_defs.rs:    "crisp-edges" => CrispEdges,
property_defs.rs:    "optimizeSpeed" => OptimizeSpeed,
property_defs.rs:    "pixelated" => Pixelated,
property_defs.rs:    "auto" => Auto,
property_defs.rs:    "isolate" => Isolate,
property_defs.rs:    "luminance" => Luminance,
property_defs.rs:    "alpha" => Alpha,
property_defs.rs:    "normal" => Normal,
property_defs.rs:    "multiply" => Multiply,
property_defs.rs:    "screen" => Screen,
property_defs.rs:    "overlay" => Overlay,
property_defs.rs:    "darken" => Darken,
property_defs.rs:    "lighten" => Lighten,
property_defs.rs:    "color-dodge" => ColorDodge,
property_defs.rs:    "color-burn" => ColorBurn,
property_defs.rs:    "hard-light" => HardLight,
property_defs.rs:    "soft-light" => SoftLight,
property_defs.rs:    "difference" => Difference,
property_defs.rs:    "exclusion" => Exclusion,
property_defs.rs:    "hue" => Hue,
property_defs.rs:    "saturation" => Saturation,
property_defs.rs:    "color" => Color,
property_defs.rs:    "luminosity" => Luminosity,
property_defs.rs:    "visible" => Visible,
property_defs.rs:    "hidden" => Hidden,
property_defs.rs:    "scroll" => Scroll,
property_defs.rs:    "auto" => Auto,
property_defs.rs:    "auto" => Auto,
property_defs.rs:    "optimizeSpeed" => OptimizeSpeed,
property_defs.rs:    "geometricPrecision" => GeometricPrecision,
property_defs.rs:    "crispEdges" => CrispEdges,
property_defs.rs:    "butt" => Butt,
property_defs.rs:    "round" => Round,
property_defs.rs:    "square" => Square,
property_defs.rs:    "miter" => Miter,
property_defs.rs:    "round" => Round,
property_defs.rs:    "bevel" => Bevel,
property_defs.rs:    "start" => Start,
property_defs.rs:    "middle" => Middle,
property_defs.rs:    "end" => End,
property_defs.rs:    "mixed" => Mixed,
property_defs.rs:    "upright" => Upright,
property_defs.rs:    "sideways" => Sideways,
property_defs.rs:    "auto" => Auto,
property_defs.rs:    "optimizeSpeed" => OptimizeSpeed,
property_defs.rs:    "optimizeLegibility" => OptimizeLegibility,
property_defs.rs:    "geometricPrecision" => GeometricPrecision,
property_defs.rs:    "normal" => Normal,
property_defs.rs:    "embed" => Embed,
property_defs.rs:    "isolate" => Isolate,
property_defs.rs:    "bidi-override" => BidiOverride,
property_defs.rs:    "isolate-override" => IsolateOverride,
property_defs.rs:    "plaintext" => Plaintext,
property_defs.rs:    "none" => None,
property_defs.rs:    "non-scaling-stroke" => NonScalingStroke,
property_defs.rs:    "visible" => Visible,
property_defs.rs:    "hidden" => Hidden,
property_defs.rs:    "collapse" => Collapse,
property_defs.rs:        "horizontal-tb" => HorizontalTb,
property_defs.rs:        "vertical-rl" => VerticalRl,
property_defs.rs:        "vertical-lr" => VerticalLr,
property_defs.rs:        "lr" => Lr,
property_defs.rs:        "lr-tb" => LrTb,
property_defs.rs:        "rl" => Rl,
property_defs.rs:        "rl-tb" => RlTb,
property_defs.rs:        "tb" => Tb,
property_defs.rs:        "tb-rl" => TbRl,
property_defs.rs:    "default" => Default,
property_defs.rs:    "preserve" => Preserve,
font_props.rs:            "small-caption" => Font::SmallCaption,
font_props.rs:                    "xx-small" => FontSize::XXSmall,
font_props.rs:                    "xx-large" => FontSize::XXLarge,
font_props.rs:                    "normal" => FontWeight::Normal,
font_props.rs:                    "bold" => FontWeight::Bold,
font_props.rs:                    "bolder" => FontWeight::Bolder,
font_props.rs:                    "lighter" => FontWeight::Lighter,
font_props.rs:                    "normal" => LetterSpacing::Normal,
transform.rs:        "matrix" => parse_prop_matrix_args(parser),
transform.rs:        "translate" => parse_prop_translate_args(parser),
transform.rs:        "translateX" => parse_prop_translate_x_args(parser),
transform.rs:        "translateY" => parse_prop_translate_y_args(parser),
transform.rs:        "scale" => parse_prop_scale_args(parser),
transform.rs:        "scaleX" => parse_prop_scale_x_args(parser),
transform.rs:        "scaleY" => parse_prop_scale_y_args(parser),
transform.rs:        "rotate" => parse_prop_rotate_args(parser),
transform.rs:        "skew" => parse_prop_skew_args(parser),
transform.rs:        "skewX" => parse_prop_skew_x_args(parser),
transform.rs:        "skewY" => parse_prop_skew_y_args(parser),
transform.rs:        "matrix" => parse_matrix_args(parser),
transform.rs:        "translate" => parse_translate_args(parser),
transform.rs:        "scale" => parse_scale_args(parser),
transform.rs:        "rotate" => parse_rotate_args(parser),
transform.rs:        "skewX" => parse_skew_x_args(parser),
transform.rs:        "skewY" => parse_skew_y_args(parser),
document.rs:        "image/png" => Ok(image::ImageFormat::Png),
document.rs:        "image/jpeg" => Ok(image::ImageFormat::Jpeg),
document.rs:        "image/gif" => Ok(image::ImageFormat::Gif),
document.rs:        "image/webp" => Ok(image::ImageFormat::WebP),
document.rs:        "image/avif" => Ok(image::ImageFormat::Avif),
aspect_ratio.rs:        "none" => None,
aspect_ratio.rs:        "xMinYMin" => Some((X(Min), Y(Min))),
aspect_ratio.rs:        "xMidYMin" => Some((X(Mid), Y(Min))),
aspect_ratio.rs:        "xMaxYMin" => Some((X(Max), Y(Min))),
aspect_ratio.rs:        "xMinYMid" => Some((X(Min), Y(Mid))),
aspect_ratio.rs:        "xMidYMid" => Some((X(Mid), Y(Mid))),
aspect_ratio.rs:        "xMaxYMid" => Some((X(Max), Y(Mid))),
aspect_ratio.rs:        "xMinYMax" => Some((X(Min), Y(Max))),
aspect_ratio.rs:        "xMidYMax" => Some((X(Mid), Y(Max))),
aspect_ratio.rs:        "xMaxYMax" => Some((X(Max), Y(Max))),
aspect_ratio.rs:        "meet" => FitMode::Meet,
aspect_ratio.rs:        "slice" => FitMode::Slice,
marker.rs:            "userSpaceOnUse" => MarkerUnits::UserSpaceOnUse,
marker.rs:            "strokeWidth" => MarkerUnits::StrokeWidth,
xml/mod.rs:                    "alternate" => alternate = Some(value),
xml/mod.rs:                    "type" => type_ = Some(value),
xml/mod.rs:                    "href" => href = Some(value),
length.rs:                    "px" => LengthUnit::Px,
length.rs:                    "em" => LengthUnit::Em,
length.rs:                    "ex" => LengthUnit::Ex,
length.rs:                    "in" => LengthUnit::In,
length.rs:                    "cm" => LengthUnit::Cm,
length.rs:                    "mm" => LengthUnit::Mm,
length.rs:                    "pt" => LengthUnit::Pt,
length.rs:                    "pc" => LengthUnit::Pc,
length.rs:                    "ch" => LengthUnit::Ch,
drawing_ctx.rs:            "'" => "\\'".to_owned(),
drawing_ctx.rs:            "\\" => "\\\\".to_owned(),
coord_units.rs:            "userSpaceOnUse" => CoordUnits::UserSpaceOnUse,
coord_units.rs:            "objectBoundingBox" => CoordUnits::ObjectBoundingBox,
filters/color_matrix.rs:            "matrix" => OperationType::Matrix,
filters/color_matrix.rs:            "saturate" => OperationType::Saturate,
filters/color_matrix.rs:            "hueRotate" => OperationType::HueRotate,
filters/color_matrix.rs:            "luminanceToAlpha" => OperationType::LuminanceToAlpha,
filters/turbulence.rs:            "stitch" => StitchTiles::Stitch,
filters/turbulence.rs:            "noStitch" => StitchTiles::NoStitch,
filters/turbulence.rs:            "fractalNoise" => NoiseType::FractalNoise,
filters/turbulence.rs:            "turbulence" => NoiseType::Turbulence,
filters/morphology.rs:            "erode" => Operator::Erode,
filters/morphology.rs:            "dilate" => Operator::Dilate,
filters/mod.rs:                    "SourceGraphic" => Input::SourceGraphic,
filters/mod.rs:                    "SourceAlpha" => Input::SourceAlpha,
filters/mod.rs:                    "BackgroundImage" => Input::BackgroundImage,
filters/mod.rs:                    "BackgroundAlpha" => Input::BackgroundAlpha,
filters/mod.rs:                    "FillPaint" => Input::FillPaint,
filters/mod.rs:                    "StrokePaint" => Input::StrokePaint,
filters/mod.rs:            "duplicate" => EdgeMode::Duplicate,
filters/mod.rs:            "wrap" => EdgeMode::Wrap,
filters/mod.rs:            "none" => EdgeMode::None,
filters/displacement_map.rs:            "R" => ColorChannel::R,
filters/displacement_map.rs:            "G" => ColorChannel::G,
filters/displacement_map.rs:            "B" => ColorChannel::B,
filters/displacement_map.rs:            "A" => ColorChannel::A,
filters/composite.rs:            "over" => Operator::Over,
filters/composite.rs:            "in" => Operator::In,
filters/composite.rs:            "out" => Operator::Out,
filters/composite.rs:            "atop" => Operator::Atop,
filters/composite.rs:            "xor" => Operator::Xor,
filters/composite.rs:            "arithmetic" => Operator::Arithmetic,
filters/component_transfer.rs:            "identity" => FunctionType::Identity,
filters/component_transfer.rs:            "table" => FunctionType::Table,
filters/component_transfer.rs:            "discrete" => FunctionType::Discrete,
filters/component_transfer.rs:            "linear" => FunctionType::Linear,
filters/component_transfer.rs:            "gamma" => FunctionType::Gamma,
filters/convolve_matrix.rs:            "false" => false,
filters/convolve_matrix.rs:            "true" => true,
filters/blend.rs:            "normal" => Mode::Normal,
filters/blend.rs:            "multiply" => Mode::Multiply,
filters/blend.rs:            "screen" => Mode::Screen,
filters/blend.rs:            "darken" => Mode::Darken,
filters/blend.rs:            "lighten" => Mode::Lighten,
filters/blend.rs:            "overlay" => Mode::Overlay,
filters/blend.rs:            "color-dodge" => Mode::ColorDodge,
filters/blend.rs:            "color-burn" => Mode::ColorBurn,
filters/blend.rs:            "hard-light" => Mode::HardLight,
filters/blend.rs:            "soft-light" => Mode::SoftLight,
filters/blend.rs:            "difference" => Mode::Difference,
filters/blend.rs:            "exclusion" => Mode::Exclusion,
filters/blend.rs:            "hue" => Mode::HslHue,
filters/blend.rs:            "saturation" => Mode::HslSaturation,
filters/blend.rs:            "color" => Mode::HslColor,
filters/blend.rs:            "luminosity" => Mode::HslLuminosity,
css.rs:            "link" => Ok(NonTSPseudoClass::Link),
css.rs:            "visited" => Ok(NonTSPseudoClass::Visited),
css.rs:            "lang" => {
css.rs:            "import" => {
angle.rs:                        "deg" => Angle::from_degrees(value),
angle.rs:                        "grad" => Angle::from_degrees(value * 360.0 / 400.0),
angle.rs:                        "rad" => Angle::new(value),
angle.rs:                        "turn" => Angle::from_degrees(value * 360.0),


```


seems quite nice!

Let's just take the first argument and then put it into a list. Here is a quick python script:

```







if __name__=="__main__":

	# First get the existing dictionary terms...

	fh = open("svg_dict.dict", "r")
	existing_terms = fh.readlines()
	fh.close()
	# Now just do the thing...
	fh = open("output.txt", "r")
	lines = fh.readlines()
	fh.close()

	# Sanity checks.

	assert isinstance(lines, list)
	assert isinstance(existing_terms, list)

	assert all([isinstance(x, str) for x in lines])
	assert all([isinstance(x, str) for x in existing_terms])

	#assert all(["\n" not in x for x in lines])
	#assert all(["\n" not in x for x in existing_terms])

	# Join the existing dictionary terms and the new terms taken from source code. This is done to avoid adding entries to the dictionary that were already there aka duplicates.

	lines = lines + existing_terms

	dict_terms = set() # Create a set, such that there are no duplicates.


	for line in lines:

		if "\"" not in line:
			continue
		line = line[line.index("\"")+1:] # Start at the character after the double quote.
		assert "\"" in line # There should be a second double quote character.
		line = line[:line.index("\"")]
		#print(line)
		assert "\n" not in line
		dict_terms.add(line)

	dict_terms = list(dict_terms)
	for term in dict_terms:
		print("\""+term+"\"") # Wrap the string in quotes, because we are making an afl dictionary...



```

which parses the output and the existing dictionary and spits out an entirely new dictionary with the other terms added! Hooray!

Here is the final dictionary:

```
"soft-light"
"spreadMethod"
"<fePointLight"
"xMidYMax"
"nonzero"
"<feFlood"
"tb"
"noStitch"
"glyph-orientation-horizontal"
"inline-table"
"darken"
"x2"
"<rect"
"standalone="
"middle"
"width"
"table-row-group"
"pad"
"<feFuncR"
"semi-expanded"
"rx"
"saturate"
"condensed"
"<meshrow"
"dominant-baseline"
"<feDisplacementMap"
"stop-color"
"in"
"evenodd"
"BackgroundImage"
"fractalNoise"
"exclusion"
"marker"
"bold"
"<animateTransform"
"optimizeSpeed"
"xMaxYMin"
"atop"
"<text"
"bevel"
"table-column"
"<style"
"userSpaceOnUse"
"<title"
"italic"
"offset"
"xMaxYMax"
"xMinYMin"
"gradientUnits"
"y2"
"<radialGradient"
"lr"
"<feFuncG"
"super"
"cx"
"<line"
"stroke-width"
"start"
"smooth"
"image/avif"
"<svg"
"baseline-shift"
"pc"
"table-footer-group"
"scaleY"
"true"
"<foreignObject"
"<mask"
"horizontal-tb"
"em"
"out"
"lr-tb"
"default"
"font-size-adjust"
"alignment-baseline"
"identity"
"table-cell"
"linear"
"baseline"
"run-in"
"plaintext"
"none"
"<hatchpath"
"bidi-override"
"<switch"
"turn"
"small-caption"
"writing-mode"
"difference"
"hard-light"
"image/jpeg"
"alternate"
"translateX"
"geometricPrecision"
"<feComponentTransfer"
"font-weight"
"'"
"bounding-Box"
"luminance"
"miter"
"ex"
"<feFuncA"
"hue"
"non-scaling-stroke"
"compact"
"visited"
"<textPath"
"<feBlend"
"<textArea"
"<polygon"
"square"
"gamma"
"table-caption"
"/>"
"font-family"
"<feSpecularLighting"
"list-item"
"ultra-expanded"
"grad"
"SourceAlpha"
"visibility"
"<feFuncB"
"ry"
"xMinYMax"
"lang"
"<discard"
"A"
"reflect"
"turbulence"
"<feTurbulence"
"vertical-lr"
"xMidYMin"
"arithmetic"
"bolder"
"high-quality"
"saturation"
"<mesh"
"<clipPath"
"<feMerge"
"inline"
"font-style"
"?>"
"href"
"cursor"
"upright"
"hueRotate"
"image/webp"
"<use"
"transform"
"lighten"
"<ellipse"
"matrix("
"xMaxYMid"
"kerning"
"overflow"
"cm"
"<animateMotion"
"stroke"
"<title>"
"<animate"
"font-variant"
"table"
"color-dodge"
"discrete"
"link"
"screen"
"px"
"G"
"<g"
"import"
"<feGaussianBlur"
"deg"
"optimizeLegibility"
"skewY"
"pt"
"false"
"<color-profile"
"overlay"
"stroke-linecap"
"rotate"
"skewX"
"<mpath"
"mixed"
"<feOffset"
"slice"
"rl-tb"
"expanded"
"transparent"
"rad"
"<hatch"
"block"
"<feDistantLight"
"extra-expanded"
"collapse"
"mm"
"type"
"scroll"
"erode"
"image/gif"
"SourceGraphic"
"normal"
"optimizeQuality"
"multiply"
"unicode-bidi"
"<feMergeNode"
"<view"
"word-spacing"
"<feMorphology"
"duplicate"
"<feTile"
"repeat"
"wider"
"<unknown"
"wrap"
"stroke-linejoin"
"translate"
"xx-large"
"table-header-group"
"rotate("
"butt"
"x1"
"vertical-rl"
"height"
"<meshgradient"
"linearRGB"
"scaleX"
"<feSpotLight"
"<script>"
"<polyline"
"stitch"
"rtl"
"<meshpatch"
"lighter"
"patternContentUnits"
"tb-rl"
"xmlns=\"
"narrower"
"<metadata"
"table-row"
"<feColorMatrix"
"skew"
"letter-spacing"
"<a"
"ultra-condensed"
"R"
"direction"
"<?xml"
"xMidYMid"
"orange"
"ch"
"sRGB"
"sub"
"<pattern"
"points"
"scale"
"luminanceToAlpha"
"<marker"
"StrokePaint"
"class"
"text-anchor"
"color-burn"
"editable"
"<set"
"<circle"
"ltr"
"<desc"
"oblique"
"pointer-events"
"table-column-group"
"sideways"
"<defs"
"<filter"
"<feImage"
"over"
"embed"
"version="
"xMinYMid"
"fill-opacity"
"luminosity"
"<path"
"alpha"
"<linearGradient"
"<script"
"strokeWidth"
"encoding="
"isolate"
"<solidcolor"
"FillPaint"
"pixelated"
"<stop"
"fill"
"small-caps"
"cy"
"stroke-dasharray"
"round"
"translateY"
"textlength"
"<feDropShadow"
"<feDiffuseLighting"
"end"
"meet"
"<![CDATA["
"stop-opacity"
"translate("
"objectBoundingBox"
"preserve"
"visible"
"hidden"
"<feComposite"
"text-decoration"
"<feConvolveMatrix"
"isolate-override"
"color-interpolation-filters"
"glyph-orientation-vertical"
"display"
"font-size"
"extra-condensed"
"rl"
"font-stretch"
"auto"
"<image"
"y1"
"semi-condensed"
"stroke-opacity"
"B"
"xor"
"image/png"
"<symbol"
"BackgroundAlpha"
"<?xml version=\"
"crispEdges"
"style"
"<tspan"
"matrix"
"xx-small"
"color"
"dilate"
"crisp-edges"
"\\"

```

## Starting fuzzing

Let the fuzzing commence with our advanced weaponry!

Here is my final fuzzing command:

```
export PYTHONPATH="."
export AFL_PYTHON_MODULE="mutator"


AFL_PYTHON_MODULE="mutator" PYTHONPATH="." cargo afl fuzz -x final_dict.dict -i minimized/ -t 300 -m 0 -o output2 -M master01 target/release/rsvg-afl-fuzz
```

## Results

Ok, so has our efforts paid off? It kinda seems like it.

I found an integer overflow in librsvg here: https://gitlab.gnome.org/GNOME/librsvg/-/issues/1115


I also idvartentantly found an integer overflow in zune_image. Here is an issue which I filed: https://github.com/etemesi254/zune-image/issues/224

## Going further

Ok, so the guy actually responded: https://gitlab.gnome.org/GNOME/librsvg/-/issues/1114#note_2192807

The original dictionary was this:

```

# Keywords taken from
#  - https://developer.mozilla.org/en-US/docs/Web/SVG/Tutorial/Introduction
#  - https://css-tricks.com/svg-properties-and-css/

"<?xml version=\"1.0\" encoding=\"utf-8\"?>"
"standalone="
"version="
"encoding="
"<?xml"
"?>"
"/>"
"<![CDATA["

# tags
"<svg"
"xmlns=\"http://www.w3.org/2000/svg\""
"<a"
"<animate"
"<animateMotion"
"<animateTransform"
"<circle"
"<clipPath"
"<color-profile"
"<defs"
"<desc"
"<discard"
"<ellipse"
"<feBlend"
"<feColorMatrix"
"<feComponentTransfer"
"<feComposite"
"<feConvolveMatrix"
"<feDiffuseLighting"
"<feDisplacementMap"
"<feDistantLight"
"<feDropShadow"
"<feFlood"
"<feFuncA"
"<feFuncB"
"<feFuncG"
"<feFuncR"
"<feGaussianBlur"
"<feImage"
"<feMerge"
"<feMergeNode"
"<feMorphology"
"<feOffset"
"<fePointLight"
"<feSpecularLighting"
"<feSpotLight"
"<feTile"
"<feTurbulence"
"<filter"
"<foreignObject"
"<g"
"<hatch"
"<hatchpath"
"<image"
"<line"
"<linearGradient"
"<marker"
"<mask"
"<mesh"
"<meshgradient"
"<meshpatch"
"<meshrow"
"<metadata"
"<mpath"
"<path"
"<pattern"
"<polygon"
"<polyline"
"<radialGradient"
"<rect"
"<rect"
"<script"
"<script>"
"<set"
"<solidcolor"
"<stop"
"<style"
"<svg"
"<switch"
"<symbol"
"<text"
"<textArea"
"<textPath"
"<title"
"<title>"
"<tspan"
"<unknown"
"<use"
"<view"


# attributes
"alignment-baseline"
"baseline-shift"
"class"
"color"
"cursor"
"cx"
"cy"
"direction"
"display"
"dominant-baseline"
"editable"
"fill"
"fill-opacity"
"font-family"
"font-size"
"font-size-adjust"
"font-stretch"
"font-style"
"font-variant"
"font-weight"
"glyph-orientation-horizontal"
"glyph-orientation-vertical"
"gradientUnits"
"height"
"kerning""
"letter-spacing"
"offset"
"overflow"
"patternContentUnits"
"pointer-events"
"points"
"rotate"
"rx"
"ry"
"spreadMethod"
"stop-color"
"stop-opacity"
"stroke"
"stroke-dasharray"
"stroke-linecap"
"stroke-linejoin"
"stroke-opacity"
"stroke-width"
"style"
"text-anchor"
"text-decoration"
"textlength"
"transform"
"unicode-bidi"
"visibility"
"width"
"word-spacing"
"writing-mode"
"x1"
"x2"
"y1"
"y2"

# attributes' values
"bounding-Box"
"repeat"
"display"
"transparent"
"orange"
"round"
"butt"
"userSpaceOnUse"
"objectBoundingBox"
"square"
"miter"
"bevel"
"translate("
"rotate("
"matrix("

```

let's figure out which entries aren't in that list.

Let's modify our script. I also noticed a bug with the escaped double quote characters. My script didn't handle those, so I am going to use rindex instead...

Here is a quick little script which I cooked up to figure out the missing entries (aka the entries which we found which weren't in the svg dictionary in the first place!)

```










if __name__=="__main__":

	# First get the existing dictionary terms...

	fh = open("svg_dict.dict", "r")
	existing_terms = fh.readlines()
	fh.close()
	# Now just do the thing...
	fh = open("output.txt", "r")
	lines = fh.readlines()
	fh.close()

	# Sanity checks.

	assert isinstance(lines, list)
	assert isinstance(existing_terms, list)

	assert all([isinstance(x, str) for x in lines])
	assert all([isinstance(x, str) for x in existing_terms])

	#assert all(["\n" not in x for x in lines])
	#assert all(["\n" not in x for x in existing_terms])

	# Join the existing dictionary terms and the new terms taken from source code. This is done to avoid adding entries to the dictionary that were already there aka duplicates.

	#lines = lines + existing_terms

	lines = lines

	dict_terms = set() # Create a set, such that there are no duplicates.


	for line in existing_terms:

		if "\"" not in line:
			continue
		line = line[line.index("\"")+1:] # Start at the character after the double quote.
		assert "\"" in line # There should be a second double quote character.
		#assert line[line.rindex("\"")-1] != "\\" # There shouldn't be an escaped double quote. The last double quote should be unescaped.
		if line[line.rindex("\"")-1] == "\\": # We shouldn't add this.
			continue
		#print("line == "+str(line))
		line = line[:line.rindex("\"")]
		#print(line)
		assert "\n" not in line
		if line not in dict_terms:

			dict_terms.add(line)



	# Now that we have the ones, which we already have, we need to check the ones which weren't in that to get the missing entries.

	for line in lines:
		if "\"" not in line:
			continue
		line = line[line.index("\"")+1:] # Start at the character after the double quote.
		assert "\"" in line # There should be a second double quote character.
		#assert line[line.rindex("\"")-1] != "\\" # There shouldn't be an escaped double quote. The last double quote should be unescaped.
		if line[line.rindex("\"")-1] == "\\": # We shouldn't add this.
			continue
		#print("line == "+str(line))
		line = line[:line.rindex("\"")]
		#print(line)
		assert "\n" not in line
		if line not in dict_terms:
			print("\"" + line + "\" wasn't in the existing dictionary!!!")
			#dict_terms.add(line)
		else:
			print("\"" + line + "\" was in the existing dictionary...")

	#dict_terms = list(dict_terms)
	#for term in dict_terms:
	#	print("\""+term+"\"") # Wrap the string in quotes, because we are making an afl dictionary...


```

the only existing entries (which were already in the dictionary) (`python3 compare.py | grep "\.\.\."`) were:

```
"miter" was in the existing dictionary...
"round" was in the existing dictionary...
"bevel" was in the existing dictionary...
"height" was in the existing dictionary...
"repeat" was in the existing dictionary...
"color" was in the existing dictionary...
"butt" was in the existing dictionary...
"round" was in the existing dictionary...
"square" was in the existing dictionary...
"miter" was in the existing dictionary...
"round" was in the existing dictionary...
"bevel" was in the existing dictionary...
"rotate" was in the existing dictionary...
"rotate" was in the existing dictionary...
"userSpaceOnUse" was in the existing dictionary...
"userSpaceOnUse" was in the existing dictionary...
"objectBoundingBox" was in the existing dictionary...
"color" was in the existing dictionary...
```

the new added entries were:

```
"color-interpolation-filters"
"pad"
"reflect"
"true"
"false"
"baseline"
"sub"
"super"
"nonzero"
"evenodd"
"auto"
"linearRGB"
"sRGB"
"ltr"
"rtl"
"inline"
"block"
"list-item"
"run-in"
"compact"
"marker"
"table"
"inline-table"
"table-row-group"
"table-header-group"
"table-footer-group"
"table-row"
"table-column-group"
"table-column"
"table-cell"
"table-caption"
"none"
"nonzero"
"evenodd"
"normal"
"wider"
"narrower"
"ultra-condensed"
"extra-condensed"
"condensed"
"semi-condensed"
"semi-expanded"
"expanded"
"extra-expanded"
"ultra-expanded"
"normal"
"italic"
"oblique"
"normal"
"small-caps"
"auto"
"smooth"
"optimizeQuality"
"high-quality"
"crisp-edges"
"optimizeSpeed"
"pixelated"
"auto"
"isolate"
"luminance"
"alpha"
"normal"
"multiply"
"screen"
"overlay"
"darken"
"lighten"
"color-dodge"
"color-burn"
"hard-light"
"soft-light"
"difference"
"exclusion"
"hue"
"saturation"
"luminosity"
"visible"
"hidden"
"scroll"
"auto"
"auto"
"optimizeSpeed"
"geometricPrecision"
"crispEdges"
"start"
"middle"
"end"
"mixed"
"upright"
"sideways"
"auto"
"optimizeSpeed"
"optimizeLegibility"
"geometricPrecision"
"normal"
"embed"
"isolate"
"bidi-override"
"isolate-override"
"plaintext"
"none"
"non-scaling-stroke"
"visible"
"hidden"
"collapse"
"horizontal-tb"
"vertical-rl"
"vertical-lr"
"lr"
"lr-tb"
"rl"
"rl-tb"
"tb"
"tb-rl"
"default"
"preserve"
"small-caption"
"xx-small"
"xx-large"
"normal"
"bold"
"bolder"
"lighter"
"normal"
"matrix"
"translate"
"translateX"
"translateY"
"scale"
"scaleX"
"scaleY"
"skew"
"skewX"
"skewY"
"matrix"
"translate"
"scale"
"skewX"
"skewY"
"image/png"
"image/jpeg"
"image/gif"
"image/webp"
"image/avif"
"none"
"xMinYMin"
"xMidYMin"
"xMaxYMin"
"xMinYMid"
"xMidYMid"
"xMaxYMid"
"xMinYMax"
"xMidYMax"
"xMaxYMax"
"meet"
"slice"
"strokeWidth"
"alternate"
"type"
"href"
"px"
"em"
"ex"
"in"
"cm"
"mm"
"pt"
"pc"
"ch"
"matrix"
"saturate"
"hueRotate"
"luminanceToAlpha"
"stitch"
"noStitch"
"fractalNoise"
"turbulence"
"erode"
"dilate"
"SourceGraphic"
"SourceAlpha"
"BackgroundImage"
"BackgroundAlpha"
"FillPaint"
"StrokePaint"
"duplicate"
"wrap"
"none"
"R"
"G"
"B"
"A"
"over"
"in"
"out"
"atop"
"xor"
"arithmetic"
"identity"
"table"
"discrete"
"linear"
"gamma"
"false"
"true"
"normal"
"multiply"
"screen"
"darken"
"lighten"
"overlay"
"color-dodge"
"color-burn"
"hard-light"
"soft-light"
"difference"
"exclusion"
"hue"
"saturation"
"luminosity"
"link"
"visited"
"lang"
"import"
"deg"
"grad"
"rad"
"turn"
```

Ok, so apparently, the added entries must be in alphabetical order, and we need to separate them into sections. There is no way I am going to spend like 30 min to sort them to individual categories. Fuck that.

## Making a custom mutator

Here I promised to create a custom mutator for svg's: https://gitlab.gnome.org/GNOME/librsvg/-/issues/1114#note_2192886 so let's do it.

First which xml parser should I use????

This seems nice: https://docs.python.org/3/library/xml.etree.elementtree.html

I only know python fluently, so I am going to use python to program the custom mutator. This will basically make it impossible to use with libfuzzer, but I don't really give a shit, because you can mod libfuzzer to use a python bridge like I did earlier in some other blog posts.

## The beginnings

(You can follow my progress here: https://github.com/personnumber3377/svg_custom_mutator )

This seems like a good start:

```


import sys
import xml.etree.ElementTree as ET # For parsing XML


def mutate_tree(tree): # Mutate tree.
	# Stub.
	return tree

def mutate(data: str) -> str: # Main mutation function.

	# First try to parse as xml (SVG is basically XML)
	root = ET.fromstring(data)
	mutate_tree(root) # Modify in-place
	mutated_contents = ET.tostring(root, encoding="utf-8") # Convert back to string representation.
	return mutated_contents

if __name__=="__main__":
	# Just take a file from sys.argv[1] and then open it, then mutate it once, then save it in sys.argv[2]

	if len(sys.argv) != 3:
		print("Usage: "+str(sys.argv[0])+" INPUT_SVG_FILE OUTPUT_SVG_FILE")

	infile = open(sys.argv[1], "rb")
	contents = infile.read()
	infile.close()

	contents = contents.decode("utf-8") # Convert to normal string.

	contents = mutate(contents) # Mutate.

	contents = contents.encode("utf-8") # Convert back to bytes

	outfile = open(sys.argv[2], "wb")
	outfile.write(contents)
	outfile.close()

	print("[+] Done!")

	exit(0) # Exit



```

my plan is to basically mutate each node in the tree with equal probability. See: https://www.geeksforgeeks.org/select-random-node-tree-equal-probability/ . After that we are going to select a mutation strategy. The three most basic ones are basically: adding a child node, removing that node entirely and modifying the node (modifying the attributes, aka changing the values or adding new attributes or removing attributes or doing the same to the actual content).

Fuck! This page: https://www.geeksforgeeks.org/select-random-node-tree-equal-probability/ only works for a binary tree, not for a tree with arbitrary amount of children.

## How to select a random node with equal probability?

Ok, so let's create a file called `select_random_node.py` where we implement this.

Something like this:

```

def get_all_paths_recursive(cur_node, current_path):
	out = [current_path]
	for i, child in enumerate(cur_node): # Loop over all child nodes...
		# print("current_path + [i] == "+str(current_path + [i]))
		# out.append(get_all_paths_recursive(child, current_path + [i]))
		out += get_all_paths_recursive(child, current_path + [i])
	return out


def get_all_paths(tree):
	return get_all_paths_recursive(tree, [])

```

then we can select a random node with this:

```
def get_all_paths(tree):
	return get_all_paths_recursive(tree, [])

def select_random_node(tree): # Select a random node with equal probability.
	all_paths = get_all_paths(tree)
	ran_path = random.choice(all_paths)
	out = tree
	for ind in ran_path:
		out = out[ind] # Traverse the tree according to the randomly chosen path.
	return out
```

seems nice.

Fuck!

We need the parent node too, because otherwise we can't fucking remove the node when mutating!

Ok, so after quite a bit of fiddling around, I am now in the commit number: 2921c1ec45975faac59f26b2c8ea18db161fe472


## Testing out our new tool

Let's see what happens, when we run it against librsvg.

... debugging time...

This was quite an interesting bug. My program seemed to generate invalid xml for some odd reason, even though I specifically designed the mutator to always create valid xml (aka SVG). This is because I didn't actually return the data which I mutated. My fuzz function looked something like this:

```

def fuzz(buf, add_buf, max_size): # Main mutation function.

	#fh = open("fuck.svg", "wb")
	#fh.write(buf)
	#fh.close()

	try:

		# First decode to ascii

		data = buf.decode("utf-8")
		assert isinstance(data, str)
		contents = mutate_func(data) # Mutate.
		#print("type(contents) == "+str(type(contents)))
		#contents = contents.encode("utf-8") # Convert back to bytes

		# The xml library adds "ns0:" strings everywhere for god knows what reason. I couldn't find anything in the docs about it so just replace all instances of that string with an empty string.


		#contents = contents.replace(b"</ns0:", b"</")
		#contents = contents.replace(b"<ns0:", b"<")
		#contents = contents.replace(b":ns0", b"")
		#print(("returning this type: "+str(type(contents))) * 100)
		contents = bytearray(contents)
	except UnicodeDecodeError:
		print("Warning! Tried to pass invalid data to the mutation function!")
		return buf # Just return the original shit.

```

after adding the `return contents` line like so:

```

def fuzz(buf, add_buf, max_size): # Main mutation function.

	#fh = open("fuck.svg", "wb")
	#fh.write(buf)
	#fh.close()

	try:

		# First decode to ascii

		data = buf.decode("utf-8")
		assert isinstance(data, str)
		contents = mutate_func(data) # Mutate.
		#print("type(contents) == "+str(type(contents)))
		#contents = contents.encode("utf-8") # Convert back to bytes

		# The xml library adds "ns0:" strings everywhere for god knows what reason. I couldn't find anything in the docs about it so just replace all instances of that string with an empty string.


		#contents = contents.replace(b"</ns0:", b"</")
		#contents = contents.replace(b"<ns0:", b"<")
		#contents = contents.replace(b":ns0", b"")
		#print(("returning this type: "+str(type(contents))) * 100)
		contents = bytearray(contents)
		return contents
	except UnicodeDecodeError:
		print("Warning! Tried to pass invalid data to the mutation function!")
		return buf # Just return the original shit.

```

and it now seems to work perfectly fine... also it took a bit of effort to figure out that the type returned must be `bytearray` . Now I am in the commit number: `8d2805942e771572af607fd8cf1ee76e29c7a35e` .

## Improving a little further

Ok, so I think the first task on the todo list is the easiest to implement. We basically just need a list of valid values for each attribute and we should be good.

I am going to add a new file called `strict_values.py` which has a list of attributes which only have a certain amount of acceptable values (like https://www.geeksforgeeks.org/svg-patternunits-attribute/ ).

Here is a complete reference for all attributes: https://www.geeksforgeeks.org/svg-attribute-complete-reference/ . I could go through them manually, but instead I am just going to fucking scrape all of those.

Just first run a curl and then grep for the links (grep for `<td><a href="https://www.geeksforgeeks.org/`) and here are all of the attribute links:

```
<td><a href="https://www.geeksforgeeks.org/svg-by-attribute/" target="_blank">by</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-cx-attribute/" target="_blank">cx</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-cy-asttribute/" target="_blank">cy</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-fill-attribute/" target="_blank">fill</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-fill-opacity-attribute/" target="_blank">fill-opacity</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-filter-attribute/" target="_blank">filter</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-flood-color-attribute/" target="_blank">flood-color</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-flood-opacity-attribute/" target="_blank">flood-opacity</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-font-size-attribute/" target="_blank">font-size</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-font-size-adjust-attribute/" target="_blank">font-size-adjust</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-font-style-attribute/" target="_blank">font-style</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-visibility-attribute/" target="_blank">visibility</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-from-attribute/" target="_blank">from</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-fr-attribute/" target="_blank">fr</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-height-attribute/" target="_blank">height</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-keypoints-attribute/" target="_blank">keyPoints</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-keytimes-attribute/" target="_blank">keyTimes</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-lengthadjust-attribute/" target="_blank">lengthAdjust</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-letter-spacing-attribute/" target="_blank">letter-spacing</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-lighting-color-attribute/" target="_blank">lighting-color</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-markerheight-attribute/" target="_blank">markerHeight</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-markerwidth-attribute/" target="_blank">markerWidth</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-mask-attribute/" target="_blank">mask</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-media-attribute/" target="_blank">media</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-numoctaves-attribute/" target="_blank">numOctaves</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-opacity-attribute/" target="_blank">opacity</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-operator-attribute/" target="_blank">operator</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-orient-attribute/" target="_blank">orient</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-path-attribute/" target="_blank">path</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-pathlength-attribute/" target="_blank">pathLength</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-patterncontentunits-attribute/" target="_blank">patternContentUnits</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-patterntransform-attribute/" target="_blank">patternTransform</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-patternunits-attribute/" target="_blank">patternUnits</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-pointer-events-attribute/" target="_blank">pointer-events</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-points-attribute/" target="_blank">points</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-pointsatx-attribute/" target="_blank">pointsAtX</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-pointsaty-attribute/" target="_blank">pointsAtY</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-pointsatz-attribute/" target="_blank">pointsAtZ</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-r-attribute/" target="_blank">r</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-radius-attribute/" target="_blank">radius</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-repeatcount-attribute/" target="_blank">repeatCount</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-repeatdur-attribute/" target="_blank">repeatDur</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-restart-attribute/" target="_blank">restart</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-rotate-attribute/" target="_blank">rotate</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-rx-attribute/" target="_blank">rx</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-ry-attribute/" target="_blank">ry</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-scale-attribute/" target="_blank">scale</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-seed-attribute/" target="_blank">seed</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-shape-rendering-attribute/" target="_blank">shape-rendering</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-startoffset-attribute/" target="_blank">startoffset</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stddeviation-attribute/" target="_blank">stdDeviation</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stitchtiles-attribute/" target="_blank">stitchTiles</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stop-color-attribute/" target="_blank">stop-color</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stop-opacity-attribute/" target="_blank">stop-opacity</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stroke-attribute/" target="_blank">stroke</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stroke-dasharray-attribute/" target="_blank">stroke-dasharray</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stroke-linecap-attribute/" target="_blank">stroke-linecap</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stroke-opacity-attribute/" target="_blank">stroke-opacity</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-stroke-width-attribute/" target="_blank">stroke-width</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-style-attribute/" target="_blank">style</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-surfacescale-attribute/" target="_blank">surfaceScale</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-systemlanguage-attribute/" target="_blank">systemLanguage</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-tabindex-attribute/" target="_blank">tabindex</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-tablevalues-attribute/" target="_blank">tableValues</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-text-anchor-attribute/" target="_blank">text-anchor</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-text-decoration-attribute/" target="_blank">text-decoration</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-text-rendering-attribute/" target="_blank">text-rendering</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-textlength-attribute/" target="_blank">textLength</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-to-attribute/" target="_blank">to</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-transform-attribute/" target="_blank">transform</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-type-attribute/" target="_blank">type</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-vector-effect-attribute/" target="_blank">vector-effect</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-visibility-attribute/" target="_blank">visibility</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-width-attribute/" target="_blank">width</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-word-spacing-attribute/" target="_blank">word-spacing</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-x-attribute/" target="_blank">x</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-x1-attribute/?ref=rp" target="_blank">x1</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-x2-attribute/" target="_blank">x2</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-xchannelselector-attribute/" target="_blank">xChannelSelector</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-xmllang-attribute/" target="_blank">xml:lang</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-y-attribute/" target="_blank">y</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-y1-attribute/" target="_blank">y1</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-y2-attribute/" target="_blank">y2</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-ychannelselector-attribute/" target="_blank">yChannelSelector</a></td>
<td><a href="https://www.geeksforgeeks.org/svg-z-attribute/" target="_blank">z</a></td>
```

easy eh?

Now do a curl on each one of those, then grep for the syntax and then if there is a pipe character (`|`) in the syntax, then it is a string thing. (I think).

This should do the job to get the webpages:

```

import os

def get_filename(line):

	assert "geeks.org/" in line
	oof = line[line.index("geeks.org/")+len("geeks.org/"):]
	oof = oof[:oof.index("/")]
	print(oof)
	return oof

if __name__=="__main__":

	fh = open("links.txt", "r")
	lines = fh.readlines()
	fh.close()

	for line in lines:
		line = line[line.index("\"")+1:] # Skip to the start of the link
		line = line[:line.index("\"")]
		print(line)
		cmd = "curl "+str(line)+" > curl_stuff/"+str(get_filename(line))
		print("Running this: "+str(cmd))
		os.system(cmd)


	exit(0)
```

now just iterate over them and see which of them have set strings.

Here is my quick and dirty script to find the stuff:

```

import os

if __name__=="__main__":

	in_dir = "curl_stuff/"

	files = os.listdir(in_dir)

	strict_vals = {}

	for file in files:
		full_filename = in_dir + file # Prepend the directory...
		attr = file[4:-10]
		#print(attr)
		fh = open(full_filename, "r")
		lines = fh.readlines()
		fh.close()
		#print("="*100)
		for i, line in enumerate(lines):
			#if file in line:
			#	print(line)

			if "Syntax: " in line and "|" in line:
				#print(line)
				line = line[line.index("Syntax: ")+len("Syntax: "):]
				#print(line)
				if "Attribute Values" in line: # Proceed normally...
					line = line[:line.index("Attribute Values")]

					if "&" in line:
						continue
					assert "=" in line
					assert line[line.index("=")+1] == " "
					line = line[line.index("=")+2:]
					#print(line)
					possible_values = line.split(" | ")
					print(possible_values)
					strict_vals[attr] = possible_values
				elif ";" in line:
					#print(line)

					line = line[:line.index(";")]


					if "Property Values:" in line:
						line = line[:line.index("Property Values:")]

					if "&" in line:
						continue
					print("Fuck fuck: "+str(line))

					line = line[line.index(" "):]

					possible_values = line.split("|")
					print("possible_values == "+str(possible_values))
					for i in range(len(possible_values)):
						val = possible_values[i]
						val = val.replace(" ", "") # Remove space characters.
						possible_values[i] = val
					assert all([" " not in val for val in possible_values])
					#print("Here is the possible values: "+str(possible_values))
					strict_vals[attr] = possible_values

				elif "Property Values:" in line:
					line = line[:line.index("Property Values:")]
					print("Fuck!!!!")
					print("ffffffffffff" + line)
					values = line[line.index(" ")+1:]
					values = values.split(" | ")
					strict_vals[attr] = values
				else:
					print("Here is the entire line: "+str(line))
					#if "</div>" in line:
					#	print("Next line: "+str(lines[i+1]))
					#	print("Next line: "+str(lines[i+2]))
					#	print("Next line: "+str(lines[i+3]))
					#	print("Next line: "+str(lines[i+4]))

				#assert "Attribute Values" in line


		#print("="*100)

	print("Here are the strict values: ")
	print(strict_vals)
	exit(0)


```

and here is the result:

```
Here are the strict values:
{'shape-rendering': ['auto', 'optimizeLegibility', 'geometricPrecision', 'optimizeSpeed '], 'lighting-color': ['currentcolor', 'color', 'icccolor '], 'text-anchor': ['auto', 'optimizeLegibility', 'geometricPrecision', 'optimizeSpeed '], 'letter-spacing': ['normal', 'length', 'initial', 'inherit'], 'stop-opacity': ['currentcolor', 'color', 'icccolor '], 'word-spacing': ['length', 'initial', 'inherit'], 'stroke-linecap': ['butt', 'round', 'square', 'initial', 'inherit'], 'text-decoration': ['none', 'underline', 'overline', 'line-through', 'initial', 'inherit'], 'pointer-events': ['auto', 'none'], 'flood-color': ['currentcolor', 'color', 'icccolor ']}
```

then I need to add manually a couple of entries::

Here is the result:

```


strict_values = {'shape-rendering': ['auto', 'optimizeLegibility', 'geometricPrecision', 'optimizeSpeed '], 'lighting-color': ['currentcolor', 'color', 'icccolor '], 'text-anchor': ['auto', 'optimizeLegibility', 'geometricPrecision', 'optimizeSpeed '], 'letter-spacing': ['normal', 'length', 'initial', 'inherit'], 'stop-opacity': ['currentcolor', 'color', 'icccolor '], 'word-spacing': ['length', 'initial', 'inherit'], 'stroke-linecap': ['butt', 'round', 'square', 'initial', 'inherit'], 'text-decoration': ['none', 'underline', 'overline', 'line-through', 'initial', 'inherit'], 'pointer-events': ['auto', 'none'], 'flood-color': ['currentcolor', 'color', 'icccolor '], 'font-size-adjust': ['number', 'none', 'initial', 'inherit']}



```

I don't know. That seems like quite little. Let's see if we are missing something... No? That actually seems like all there are!! Great!

## Making a generic string mutator.

Ok, so instead of just randomly generating a random string each time when mutating a string, we should just mutate the string actually. Let's create a new repository and then create a generic mutator and import that mutator to this mutator. Here is my generic mutator: https://github.com/personnumber3377/generic_mutator

Here is a quick little demo:

```

import random
import string # string.printable

def remove_substring(string: str) -> str:
	start_index = random.randrange(len(string)-1)
	end_index = random.randrange(start_index, len(string))
	return string[:start_index] + string[end_index:]

def multiply_substring(string: str) -> str:
	start_index = random.randrange(len(string)-1)
	end_index = random.randrange(start_index, len(string))
	substr = string[start_index:end_index]
	where_to_place = random.randrange(len(string)-1)
	return string[:where_to_place] + substr + string[where_to_place:]

def add_character(string: str) -> str:
	where_to_place = random.randrange(len(string)-1)
	return string[:where_to_place] + random.choice(string.printable) + string[where_to_place:]

def mutate(string: str) -> str: # Mutate a string.

	strat = random.randrange(3)

	match strat:
		case 0:
			# Remove substring
			return remove_substring(string)
		case 1:
			# Multiply substring.
			return multiply_substring(string)
		case 2:
			# Add a character somewhere
			return add_character(string)
		case _:
			print("Invalid")
			assert False
	print("Invalid")
	assert False


```

then after a bit of testing, here is the final result:

```


import random
import string as string_mod # string.printable

def remove_substring(string: str) -> str:
	start_index = random.randrange(max(len(string)-1, 1))
	end_index = random.randrange(start_index, len(string))
	return string[:start_index] + string[end_index:]

def multiply_substring(string: str) -> str:
	start_index = random.randrange(max(len(string)-1, 1))
	end_index = random.randrange(start_index, len(string))
	substr = string[start_index:end_index]
	where_to_place = random.randrange(max(len(string)-1, 1))
	return string[:where_to_place] + substr + string[where_to_place:]

def add_character(string: str) -> str:
	#if len(string)-1 >= 1:

	where_to_place = random.randrange(max(len(string)-1, 1))

	return string[:where_to_place] + random.choice(string_mod.printable) + string[where_to_place:]

def mutate_generic(string: str) -> str: # Mutate a string.

	strat = random.randrange(3)

	match strat:
		case 0:
			# Remove substring
			return remove_substring(string)
		case 1:
			# Multiply substring.
			return multiply_substring(string)
		case 2:
			# Add a character somewhere
			return add_character(string)
		case _:
			print("Invalid")
			assert False
	print("Invalid")
	assert False



```

## Fuzzing results.

Ok, so after fuzzing with our custom mutator. I managed to find quite an interesting assertion failure, though it is in the `cssparser` package: https://gitlab.gnome.org/GNOME/librsvg/-/issues/1117 , but I think it is still a bug in librsvg, because the library expects the values to be non-malformed before passing to it. I also managed to rediscover the integer overflow: https://gitlab.gnome.org/GNOME/librsvg/-/issues/1115

## Fixing crashes and continuing fuzzing.

Let's add the patches for the stuff and apply them and compile the fuzzers again.

...

after a bit of fuzzing, it looks like all the crashes which it finds are in the cairo library. Not in the librsvg library. Therefore we need to make the fuzzer a bit better.

## Making the href mutator and the id thing mutator and url thing mutator.








## TODO:

- (Complete) Add a way to process attributes such as "patternUnits" which only has a very specific set of valid input strings (see https://www.geeksforgeeks.org/svg-patternunits-attribute/) I think this can be done by just having a list of acceptable values for each of these types of attributes and then just randomly choosing one.
- Add some attribute handlers for the "filter" attribute.
- Add some support for the "url" type stuff like here: https://www.geeksforgeeks.org/svg-patternunits-attribute/ (see the `url(#geek1)`) . I think this could be quite a nice addition.
- (Complete) Add a generic string mutator. (This could be useful to mutate just normally maybe?)
- Add a content mutator (a mutator which changes the contents of a tag instead of attributes).
- Generate different kinds of numbers. Now the numbers we are generating are almost always obscenely large. I think we should add probabilities to generate just floats between zero and one etc etc etc..





