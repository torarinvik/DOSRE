CXX ?= c++
CXXFLAGS ?= -O2 -std=c++17 -Wall -Wextra -Wpedantic

BIN := bin16_promote_wasm

all: $(BIN)

$(BIN): bin16_promote_wasm.cpp
	$(CXX) $(CXXFLAGS) -o $(BIN) bin16_promote_wasm.cpp

clean:
	rm -f $(BIN)
