#!/bin/bash

repo=
folder=

if [ "$1" != "" ]; then
  case $1 in
    -r | --repo)
      shift
      repo=$1
      ;;
    -f | --folder)
      shift
      folder=$1
      ;;
  esac
fi

if [ "$repo" != "" ]; then
  python3 ../shefmine.py $repo
fi

if [ "$folder" != "" ]; then
  case $folder in
    all)
      for lang in ../repositories/* ; do
        for repo in $lang/* ; do
          python3 ../shefmine.py $repo
        done
      done
      ;;
    c)
      for lang in ../repositories/c ; do
        for repo in $lang/* ; do
          python3 ../shefmine.py $repo
        done
      done
      ;;
    java)
      for lang in ../repositories/java ; do
        for repo in $lang/* ; do
          python3 ../shefmine.py $repo
        done
      done
      ;;
    python)
      for lang in ../repositories/python ; do
        for repo in $lang/* ; do
          python3 ../shefmine.py $repo
        done
      done
      ;;
  esac
fi
