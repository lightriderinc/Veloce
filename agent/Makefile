# Veloce Agent build. The two crypto backends compile against the header
# sets of the exact library builds they dlopen (spec 5.2, 5.3), so struct
# layouts always match the loaded module.
ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST)))/..)
BUILD := $(ROOT)/build/agent-obj
BIN := $(ROOT)/build/bin

FIPS_INC := $(ROOT)/build/fips-src
PQC_INC := $(ROOT)/build/pqc-src/wolfssl-5.9.2-stable
PQC_CFG := $(ROOT)/scripts/pqc

CXX ?= g++
CXXFLAGS := -std=c++17 -O2 -Wall -Wextra -pthread

OBJS := $(BUILD)/main.o $(BUILD)/fips_core.o $(BUILD)/pqc_core.o

all: $(BIN)/veloce-agent

$(BUILD) $(BIN):
	mkdir -p $@

$(BUILD)/main.o: src/main.cpp src/json.hpp src/keystore.hpp \
		src/fips_core.hpp src/pqc_core.hpp | $(BUILD)
	$(CXX) $(CXXFLAGS) -c $< -o $@

$(BUILD)/fips_core.o: src/fips_core.cpp src/fips_core.hpp src/sha256.hpp \
		| $(BUILD)
	$(CXX) $(CXXFLAGS) -I$(FIPS_INC) -c $< -o $@

$(BUILD)/pqc_core.o: src/pqc_core.cpp src/pqc_core.hpp src/sha256.hpp \
		| $(BUILD)
	$(CXX) $(CXXFLAGS) -DWOLFSSL_USER_SETTINGS -I$(PQC_CFG) -I$(PQC_INC) \
		-c $< -o $@

$(BIN)/veloce-agent: $(OBJS) | $(BIN)
	$(CXX) $(CXXFLAGS) -o $@ $(OBJS) -ldl

clean:
	rm -rf $(BUILD) $(BIN)/veloce-agent

.PHONY: all clean
