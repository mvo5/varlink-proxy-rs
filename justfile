destdir := env("DESTDIR", "")
prefix := "/usr"
bindir := prefix / "bin"
unitdir := prefix / "lib/systemd/system"
bridgedir := prefix / "lib/systemd/varlink-bridges"

install: install_server install_client

install_server: (build "release")
	install -Dm755 {{srv_binary}} {{destdir}}{{bindir}}/varlink-http-bridge
	install -dm755 {{destdir}}{{unitdir}}
	sed 's|@bindir@|{{bindir}}|g' data/varlink-http-bridge.service.in > {{destdir}}{{unitdir}}/varlink-http-bridge.service

install_client: (build "release")
	install -Dm755 {{helper_binary}} {{destdir}}{{bridgedir}}/http
	ln -sf http {{destdir}}{{bridgedir}}/https
	ln -sf http {{destdir}}{{bridgedir}}/ws
	ln -sf http {{destdir}}{{bridgedir}}/wss

[private]
build profile:
	cargo build --profile {{profile}}

check: check_srv_binary_size check_helper_binary_size
	cargo fmt --check
	cargo clippy -- -W clippy::pedantic

test *args:
	cargo test {{args}}

# the httpd service
srv_binary := "target/release/varlink-http-bridge"
# max_size_kb is a bit arbitrary but it should ensure we don't increase size too much
# without noticing (currently at 3.2MB)
srv_max_size := "4 * 1024 * 1024"

# the varlinkctl helper binary so that varlinkctl exec:varlinkctl-helper can talk to http
helper_binary := "target/release/varlinkctl-helper"
helper_max_size := "2 * 1024 * 1024"

[script]
check_srv_binary_size:
	cargo build --release
	max_size_kb="$(({{srv_max_size}} / 1024 ))"
	cur_size_kb=$(( $(stat --format='%s' {{srv_binary}}) / 1024 ))
	echo "release binary: ${cur_size_kb}KB / ${max_size_kb}KB"
	if [ "$cur_size_kb" -gt "$max_size_kb" ]; then
	  echo "ERROR: release binary exceeds limit"
	  exit 1
	fi

[script]
check_helper_binary_size:
	cargo build --release
	max_size_kb="$(({{helper_max_size}} / 1024 ))"
	cur_size_kb=$(( $(stat --format='%s' {{helper_binary}}) / 1024 ))
	echo "release varlinkctl-helper binary: ${cur_size_kb}KB / ${max_size_kb}KB"
	if [ "$cur_size_kb" -gt "$max_size_kb" ]; then
	  echo "ERROR: release varlinkctl-helper binary exceeds limit"
	  exit 1
	fi

container_image := "varlink-http-bridge-test"
container_name := "vhb-test"

# Run cargo test inside a Fedora system container (systemd as PID 1)
[script]
test-in-container *args:
	if ! podman image exists "{{container_image}}"; then
	  podman build -t "{{container_image}}" -f Containerfile.test .
	fi
	podman rm -f "{{container_name}}" 2>/dev/null || true
	trap 'podman rm -f "{{container_name}}"' EXIT
	podman run -d --systemd=true \
	  --name "{{container_name}}" \
	  -v .:/srv/varlink-http-bridge:z \
	  -w /srv/varlink-http-bridge \
	  "{{container_image}}"
	podman exec "{{container_name}}" systemctl is-system-running --wait || true
	podman exec "{{container_name}}" cargo test {{args}}
