#!/usr/bin/env bash

for i in $(fd -e .py .); do
  bash -c awk '{gsub(/"/, "'"); print}' $i
done

