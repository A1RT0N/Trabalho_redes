# Makefile para slow_peripheral

CXX        := g++
CXXFLAGS   := -std=c++17 -Wall -Wextra -O2 -pthread
LDFLAGS    := -pthread -luuid

TARGET     := slow_peripheral
SRC        := slow_peripheral.cpp

.PHONY: all clean install test test-local debug release dist help

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f $(TARGET) *.o

install: $(TARGET)
	cp $(TARGET) /usr/local/bin/

# Testa contra slow.gmelodie.com
test: $(TARGET)
	@echo "Executando teste contra slow.gmelodie.com"
	./$(TARGET) slow.gmelodie.com

# Teste local
test-local: $(TARGET)
	@echo "Executando teste local no 127.0.0.1"
	./$(TARGET) 127.0.0.1

# Build para depuração
debug: CXXFLAGS += -g -DDEBUG
debug: clean all

# Build release com ainda mais otimizações
release: CXXFLAGS += -O3 -DNDEBUG
release: clean all

# Empacotamento para distribuição
dist: clean
	tar -czf slow_peripheral.tar.gz $(SRC) Makefile README.md

help:
	@echo "Uso do Makefile:"
	@echo "  make          - compila $(TARGET)"
	@echo "  make clean    - remove binários e objetos"
	@echo "  make install  - instala em /usr/local/bin"
	@echo "  make test     - executa ./$(TARGET) slow.gmelodie.com"
	@echo "  make test-local - executa ./$(TARGET) 127.0.0.1"
	@echo "  make debug    - build com símbolos de debug"
	@echo "  make release  - build otimizado para release"
	@echo "  make dist     - gera slow_peripheral.tar.gz"
	@echo "  make help     - mostra esta mensagem"