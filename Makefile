# Veloce PQC SDK build entry points. See docs/quickstart.md.
.PHONY: all fips pqc agent rust config test wheel clean

all: fips pqc agent rust config

fips:
	bash scripts/build_fips.sh

pqc:
	bash scripts/build_pqc.sh

agent:
	$(MAKE) -C agent

rust:
	cd qsearch && PATH="$$HOME/.cargo/bin:$$PATH" cargo build --release
	cd cli && PATH="$$HOME/.cargo/bin:$$PATH" cargo build --release
	mkdir -p build/bin
	cp qsearch/target/release/qsearch cli/target/release/veloce build/bin/

config:
	python3 scripts/gen_config.py

# Release gate battery (spec 9): the one command to test everything.
test:
	bash scripts/run_gates.sh

wheel:
	cd python && python3 -m pip wheel --no-deps -w ../build/dist .

clean:
	rm -rf build/agent-obj build/bin build/pqc-obj
	$(MAKE) -C agent clean
