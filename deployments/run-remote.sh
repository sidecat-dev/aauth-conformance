#!/bin/bash
# Build the reference deployments, start them as HTTPS servers on this
# machine and run the suite's remote mode against each: aauth-go and
# aauth-rust from the checkouts named, and the aauth-protocol crates at the
# versions deployments/aauth-protocol pins.
#
# Usage: deployments/run-remote.sh /path/to/aauth-go /path/to/aauth-rust OUT
#
# deployments/roles/*.json say what the aauth-go and aauth-rust deployments
# serve: "names" are server names (LIB stands for go or rust), "trusted" the
# further suite parties they trust, and "roles" the deployment file's roles.
# Optional environment: LIBS (default "go rust protocol") picks the
# deployments; REMOTE_ROLES (space-separated) keeps only those suite roles;
# CARGO_TARGET is a reusable Cargo target directory.
#
# Everything runs on loopback. A test CA made here signs a certificate for
# the suite's party names and one for each deployment's names; every name is
# routed to its port with -resolve (the suite) or the deployment's "resolve"
# map, so no DNS or hosts entries are needed. Reports land in
# OUT/remote-aauth-LIB/. Needs Go 1.25 or later, rustup, openssl and jq.
set -euo pipefail
go_source=$(realpath "${1:?aauth-go checkout}")
rust_source=$(realpath "${2:?aauth-rust checkout}")
mkdir -p "${3:?output directory}"
out=$(realpath "$3")
here=$(dirname "$(realpath "$0")")
suite=$(dirname "$here")
work="$out/work"; rm -rf "$work"; mkdir -p "$work"
libs=${LIBS:-go rust protocol}
target=${CARGO_TARGET:-$work/rust-target}
wanted() { case " $libs " in *" $1 "*) return 0 ;; esac; return 1; }

echo "== build"
ln -sfn "$go_source" "$here/aauth-go/library"
ln -sfn "$rust_source" "$here/aauth-rust/library"
(cd "$suite" && CGO_ENABLED=0 go build -o "$work/aauth-conformance" ./cmd/aauth-conformance)
if wanted go; then (cd "$here/aauth-go" && go build -o "$work/aauth-go-deployment" .); fi
if wanted rust; then (cd "$here/aauth-rust" && cargo build --release --target-dir "$target" &&
  cp "$target/release/aauth-rust-deployment" "$work/"); fi
if wanted protocol; then (cd "$here/aauth-protocol" && cargo build --release --locked --target-dir "$target" &&
  cp "$target/release/aauth-protocol-deployment" "$work/"); fi

cd "$work"
SUITE=127.0.0.1:18443
declare -A PORT=([go]=127.0.0.1:18444 [rust]=127.0.0.1:18445 [protocol]=127.0.0.1:18446)
suite_names=$(./aauth-conformance -suite "$suite" -harness-names | tr '\n' ' ')
# One merged description of what the library deployments serve.
jq -s '{names: (map(.names // {}) | add), trusted: (map(.trusted // []) | add | unique), roles: (map(.roles // {}) | add)}' \
  "$here"/roles/*.json > roles.json
if [ -n "${REMOTE_ROLES:-}" ]; then
  jq --arg keep "$REMOTE_ROLES" '.roles |= with_entries(select(.key as $k | $keep | split(" ") | index($k)))' roles.json > kept.json
  mv kept.json roles.json
fi
for_lib() { sed "s/aauth-LIB\./aauth-$1./g; s/LIB/$1/g" roles.json; }
names() {
  case $1 in
  protocol) echo "api.aauth-protocol.test person.aauth-protocol.test" ;;
  *) for_lib "$1" | jq -r '.names[]' | sed 's#^https://##; s#[/:].*##' | sort -u | tr '\n' ' ' ;;
  esac
}

echo "== test certificates"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout ca.key -out ca.pem -days 2 \
  -subj /CN=remote-mode-test-ca -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
leaf() {
  local sans; sans=$(for n in $2; do printf 'DNS:%s,' "$n"; done); sans=${sans%,}
  openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=$1" 2>/dev/null
  openssl x509 -req -in "$1.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -out "$1.pem" -days 2 \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\n' "$sans") 2>/dev/null
}
leaf suite "$suite_names"
for lib in $libs; do leaf "$lib" "$(names "$lib")"; done

# A deployment reaches the suite's names at the suite and its own at itself.
resolve() {
  { for n in $suite_names; do printf '%s:443\t%s\n' "$n" "$SUITE"; done
    for n in $(names "$1"); do printf '%s:443\t%s\n' "$n" "${PORT[$1]}"; done; } |
    jq -R -s 'split("\n") | map(select(length > 0) | split("\t") | {(.[0]): .[1]}) | add'
}
revision() {
  local tag; tag=$(git -C "$1" describe --tags --exact-match 2>/dev/null || true)
  echo "${tag:+$tag }$(git -C "$1" rev-parse --short=7 HEAD)"
}
for lib in go rust; do
  wanted $lib || continue
  source=$go_source; [ $lib = rust ] && source=$rust_source
  for_lib $lib | jq --arg listen "${PORT[$lib]}" --arg work "$work" --arg lib "$lib" --argjson resolve "$(resolve $lib)" '
    .names + {listen: $listen, cert: "\($work)/\($lib).pem", key: "\($work)/\($lib).key", ca: "\($work)/ca.pem", resolve: $resolve,
      agent_providers: ["https://ap.conformance.test"], person_servers: ["https://person.conformance.test"],
      resources: ["https://resource.conformance.test"], names: .names, trusted: .trusted}' > "$lib-server.json"
  for_lib $lib | jq --arg id "aauth-$lib" --arg revision "$(revision "$source")" \
    '{version: 1, id: $id, revision: $revision, roles: .roles}' > "deployment-$lib.json"
done
if wanted protocol; then
  jq -n --arg listen "${PORT[protocol]}" --arg work "$work" --argjson resolve "$(resolve protocol)" '
    {listen: $listen, cert: "\($work)/protocol.pem", key: "\($work)/protocol.key", ca: "\($work)/ca.pem", resolve: $resolve,
     identity_resource: "https://api.aauth-protocol.test", direct_person_server: "https://person.aauth-protocol.test",
     agent_providers: ["https://ap.conformance.test"]}' > protocol-server.json
  cp "$here/aauth-protocol/deployment.json" deployment-protocol.json
fi

echo "== start deployments"
pids=()
trap 'kill "${pids[@]}" 2>/dev/null || true' EXIT
for lib in $libs; do
  case $lib in
  go) ./aauth-go-deployment -config go-server.json > "$out/aauth-go-server.log" 2>&1 & ;;
  *) "./aauth-$lib-deployment" "$lib-server.json" > "$out/aauth-$lib-server.log" 2>&1 & ;;
  esac
  pids+=($!)
done
for lib in $libs; do
  address=${PORT[$lib]}
  for _ in $(seq 30); do (echo > "/dev/tcp/${address%:*}/${address#*:}") 2>/dev/null && break; sleep 1; done
done

status=0
for lib in $libs; do
  flags=(-ca ca.pem -tls-cert suite.pem -tls-key suite.key -listen "$SUITE")
  for n in $(names $lib); do flags+=(-resolve "$n:443=${PORT[$lib]}"); done
  echo "== remote mode against aauth-$lib"
  ./aauth-conformance -suite "$suite" -remote "deployment-$lib.json" -out "$out/remote-aauth-$lib" "${flags[@]}" || status=$?
done
exit $status
