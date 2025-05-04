#!/usr/bin/env bash

for i in $(fd -e .py .); do
  black $i;
done

