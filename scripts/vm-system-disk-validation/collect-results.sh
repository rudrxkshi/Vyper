#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
  echo "Usage: $0 RESULT_DIRECTORY OUTPUT_ARCHIVE.tar.gz" >&2
  exit 2
fi

result_directory=$1
archive=$2
test -d "$result_directory"

find "$result_directory" -type f ! -name SHA256SUMS -print0 | sort -z | xargs -0 sha256sum > "$result_directory/SHA256SUMS"
tar --create --gzip --file "$archive" --directory "$(dirname "$result_directory")" "$(basename "$result_directory")"
sha256sum "$archive"
echo "Result collection is read-only with respect to VM disks; preserve the source directory until review completes."
