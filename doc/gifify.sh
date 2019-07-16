#!/bin/bash

# Run this in the directory containing the dot-files:
# - turns dot-files into png's
# - turns the png's into animated gif.

# Notes
# - ffmpeg conversion creates yellow color for originally black text/lines
# - convert conversion seems to leak images through to other gif frames


for f in $(ls *.dot); do
    echo "dot -Tpng ${f} > ${f/.dot/.png}";
    dot -Tpng ${f} > ${f/.dot/.png};
done

# Alternative using ImageMagick:
# convert -resize 900x600 -delay 150 -loop 0 *.png cnv.gif

echo "\nConverting to gif"

ffmpeg \
  -framerate 1 \
  -pattern_type glob \
  -i './*.png' \
  -r 1 \
  -vf scale=492:-1 \
  out.gif \
;

  # -vf scale=500:1248 \
