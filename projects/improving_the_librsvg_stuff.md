
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











