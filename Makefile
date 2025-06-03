CXX = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2 -pthread
LDFLAGS = -pthread -luuid

TARGET = slow_peripheral
SOURCE = slow_peripheral.cpp

.PHONY: all clean install test

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CXX) $(CXXFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

test: $(TARGET)
	./$(TARGET) slow.gmelodie.com

# Alternative test with localhost (if testing locally)
test-local: $(TARGET)
	./$(TARGET) 127.0.0.1

# Debug build
debug: CXXFLAGS += -g -DDEBUG
debug: $(TARGET)

# Release build with optimizations
release: CXXFLAGS += -O3 -DNDEBUG
release: $(TARGET)

# Create distribution tarball
dist: clean
	tar -czf slow_peripheral.tar.gz *.cpp *.h Makefile README.md

help:
	@echo "Available targets:"
	@echo "  all      - Build the peripheral (default)"
	@echo "  clean    - Remove built files"
	@echo "  install  - Install to /usr/local/bin"
	@echo "  test     - Test with slow.gmelodie.com"
	@echo "  debug    - Build with debug symbols"
	@echo "  release  - Build optimized release version"
	@echo "  dist     - Create distribution tarball"
	@echo "  help     - Show this help message"