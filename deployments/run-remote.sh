#!/bin/bash
# Build the reference deployments, start them as HTTPS servers on this
# machine and run the suite's remote mode against each: aauth-go and
# aauth-rust from the checkouts named, and the aauth-protocol crates at the
# versions deployments/aauth-protocol pins.
#
# Usage: deployments/run-remote.sh /path/to/aauth-go /path/to/aauth-rust OUT
#
# Everything runs on loopback. A test CA made here signs a certificate for
# the suite's party names and one for each deployment's names; every name is
# routed to its port with -resolve (the suite) or the deployment's "resolve"
# map, so no DNS or hosts entries are needed. Reports land in
# OUT/remote-aauth-go/, OUT/remote-aauth-rust/ and OUT/remote-aauth-protocol/.
set -euo pipefail
go_source=$(realpath "${1:?aauth-go checkout}")
rust_source=$(realpath "${2:?aauth-rust checkout}")
mkdir -p "${3:?output directory}"
out=$(realpath "$3")
here=$(dirname "$(realpath "$0")")
suite=$(dirname "$here")
work="$out/work"; rm -rf "$work"; mkdir -p "$work"

echo "== build"
ln -sfn "$go_source" "$here/aauth-go/library"
ln -sfn "$rust_source" "$here/aauth-rust/library"
(cd "$suite" && CGO_ENABLED=0 go build -o "$work/aauth-conformance" ./cmd/aauth-conformance)
(cd "$here/aauth-go" && go build -o "$work/aauth-go-deployment" .)
(cd "$here/aauth-rust" && cargo build --release --target-dir "$work/rust-target" &&
  cp "$work/rust-target/release/aauth-rust-deployment" "$work/")
(cd "$here/aauth-protocol" && cargo build --release --locked --target-dir "$work/rust-target" &&
  cp "$work/rust-target/release/aauth-protocol-deployment" "$work/")

cd "$work"
SUITE=127.0.0.1:18443
declare -A PORT=([go]=127.0.0.1:18444 [rust]=127.0.0.1:18445 [protocol]=127.0.0.1:18446)
suite_names="ap.conformance.test resource.conformance.test person.conformance.test"
names() {
  case $1 in
  protocol) echo "api.aauth-protocol.test person.aauth-protocol.test" ;;
  *) echo "api.aauth-$1.test person.aauth-$1.test records.aauth-$1.test ps.aauth-$1.test access.aauth-$1.test" ;;
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
leaf suite "$suite_names"; leaf go "$(names go)"; leaf rust "$(names rust)"; leaf protocol "$(names protocol)"

# A deployment reaches the suite's names at the suite and its own at itself.
resolve() {
  local first=1; printf '{'
  for n in $suite_names; do [ $first = 1 ] || printf ','; first=0; printf '"%s:443":"%s"' "$n" "$SUITE"; done
  for n in $(names "$1"); do printf ',"%s:443":"%s"' "$n" "${PORT[$1]}"; done
  printf '}'
}
revision() {
  local tag; tag=$(git -C "$1" describe --tags --exact-match 2>/dev/null || true)
  echo "${tag:+$tag }$(git -C "$1" rev-parse --short=7 HEAD)"
}
for lib in go rust; do
  source=$go_source; [ $lib = rust ] && source=$rust_source
  cat > "$lib-server.json" <<JSON
{"listen":"${PORT[$lib]}","cert":"$work/$lib.pem","key":"$work/$lib.key","ca":"$work/ca.pem","resolve":$(resolve $lib),
 "identity_resource":"https://api.aauth-$lib.test","direct_person_server":"https://person.aauth-$lib.test",
 "federated_resource":"https://records.aauth-$lib.test","federated_person_server":"https://ps.aauth-$lib.test",
 "access_server":"https://access.aauth-$lib.test",
 "agent_providers":["https://ap.conformance.test"],"person_servers":["https://person.conformance.test"],
 "resources":["https://resource.conformance.test"]}
JSON
  cat > "deployment-$lib.json" <<JSON
{"version":1,"id":"aauth-$lib","revision":"$(revision "$source")","roles":{
 "resource.agent-identity":{"resource":"https://api.aauth-$lib.test/whoami"},
 "person-server.direct":{"person_server":"https://person.aauth-$lib.test"},
 "authorization.federated":{"resource":"https://records.aauth-$lib.test/records",
   "person_server":"https://ps.aauth-$lib.test","access_server":"https://access.aauth-$lib.test"}}}
JSON
done
cat > protocol-server.json <<JSON
{"listen":"${PORT[protocol]}","cert":"$work/protocol.pem","key":"$work/protocol.key","ca":"$work/ca.pem","resolve":$(resolve protocol),
 "identity_resource":"https://api.aauth-protocol.test","direct_person_server":"https://person.aauth-protocol.test",
 "agent_providers":["https://ap.conformance.test"]}
JSON
cp "$here/aauth-protocol/deployment.json" deployment-protocol.json

echo "== start deployments"
./aauth-go-deployment -config go-server.json > "$out/aauth-go-server.log" 2>&1 & go_pid=$!
./aauth-rust-deployment rust-server.json > "$out/aauth-rust-server.log" 2>&1 & rust_pid=$!
./aauth-protocol-deployment protocol-server.json > "$out/aauth-protocol-server.log" 2>&1 & protocol_pid=$!
trap 'kill $go_pid $rust_pid $protocol_pid 2>/dev/null || true' EXIT
for address in "${PORT[@]}"; do
  for _ in $(seq 30); do (echo > "/dev/tcp/${address%:*}/${address#*:}") 2>/dev/null && break; sleep 1; done
done

status=0
for lib in go rust protocol; do
  flags=(-ca ca.pem -tls-cert suite.pem -tls-key suite.key -listen "$SUITE")
  for n in $(names $lib); do flags+=(-resolve "$n:443=${PORT[$lib]}"); done
  echo "== remote mode against aauth-$lib"
  ./aauth-conformance -suite "$suite" -remote "deployment-$lib.json" -out "$out/remote-aauth-$lib" "${flags[@]}" || status=$?
done
exit $status
