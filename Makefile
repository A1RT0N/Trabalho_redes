# Makefile para slow_peripheral

CXX        := g++
CXXFLAGS   := -std=c++17 -Wall -Wextra -O2 -pthread
LDFLAGS    := -pthread

TARGET     := slow_peripheral
SRC        := slow_peripheral.cpp

.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

run: all
	@echo "Executando cliente UDP Peripheral..."
	./$(TARGET)

clean:
	rm -f $(TARGET)
