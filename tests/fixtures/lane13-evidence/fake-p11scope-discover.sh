#!/bin/sh
module=; output=; previous=
for argument do
    [ "$previous" = --module ] && module=$argument
    [ "$previous" = -o ] && output=$argument
    previous=$argument
done
printf '{"schema":"p11scope-manifest/5","module_path":"%s","objects":[{"path":"%s"}]}\n' "$module" "$module" > "$output"
