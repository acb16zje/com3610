#!/bin/bash

for lang in ../repositories/*/ ; do
  (cd "$lang" && for repo in ./*/ ; do
    (cd "$repo" && git fetch);
  done );
done
