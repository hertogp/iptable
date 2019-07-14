#!/bin/bash

for f in $(ls *.dot); do
    echo "dot -Tpng ${f} > ${f/.dot/.png}";
    dot -Tpng ${f} > ${f/.dot/.png};
done

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
