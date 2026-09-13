#!/usr/bin/env bash
set -euo pipefail

runs="${1:-10}"
output_dir="${2:-build/benchmark-$(date -u +%Y%m%dT%H%M%SZ)}"

if ! [[ "${runs}" =~ ^[1-9][0-9]*$ ]]; then
  echo "runs must be a positive integer" >&2
  exit 2
fi

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
results_path="${repo_root}/${output_dir}/results.csv"
environment_path="${repo_root}/${output_dir}/environment.txt"
compiler="${CC:-cc}"

mkdir -p "${repo_root}/${output_dir}"
if [[ -e "${results_path}" || -e "${environment_path}" ]]; then
  echo "refusing to overwrite existing benchmark output in ${output_dir}" >&2
  exit 2
fi

cd "${repo_root}"
make -s build/benchmark_p1 build/benchmark_p2 build/benchmark_p3

{
  date -u +"utc_time=%Y-%m-%dT%H:%M:%SZ"
  printf 'git_commit='
  git rev-parse HEAD
  printf 'compiler_command=%s\n' "${compiler}"
  "${compiler}" --version
  make -s print-build-config
  uname -a
  lscpu
} > "${environment_path}"

for ((run = 1; run <= runs; ++run)); do
  echo "benchmark repetition ${run}/${runs}" >&2
  if ((run == 1)); then
    ./build/benchmark_p1 >> "${results_path}"
  else
    ./build/benchmark_p1 --no-header >> "${results_path}"
  fi
  ./build/benchmark_p2 --no-header >> "${results_path}"
  ./build/benchmark_p3 --no-header >> "${results_path}"
done

printf 'results=%s\n' "${results_path}"
printf 'environment=%s\n' "${environment_path}"
