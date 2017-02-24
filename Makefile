BIN = shabang
SRC = $(wildcard *.cpp)
LIBBLOOM = libbloom/build/libbloom.a
LIBSHA_DIGEST = sha_digest/libsha_digest.a
OBJ = $(patsubst %.cpp, %.o, $(SRC))
LIBS += -lm -lpthread -lleveldb -lboost_system -lboost_thread -lboost_program_options

#CFLAGS += -Wall -Wextra -pedantic -std=c++11
CXX = clang++
CFLAGS += -Weverything -pedantic -std=c++11 -Wno-padded -Wno-c++98-compat-pedantic -Wno-weak-vtables


.PHONY: all
all: $(BIN)

.PHONY: debug
debug: $(BIN)-debug

.cpp.o:
	$(CXX) -c -o $@ $< $(CFLAGS)

$(BIN): $(OBJ) $(LIBSHA_DIGEST) $(LIBBLOOM)
	$(CXX) -o $@ $^ $(CFLAGS) -O3 -march=native $(LIBS) $(LDFLAGS)
	strip $@

$(BIN)-debug: $(OBJ) $(LIBSHA_DIGEST) $(LIBBLOOM)
	$(CXX) -o $@ $^ $(CFLAGS) -O0 -DDEBUG -pg -g $(LIBS) $(LDFLAGS)

$(LIBBLOOM):
	$(MAKE) -C libbloom

$(LIBSHA_DIGEST):
	$(MAKE) -C sha_digest

.PHONY: prof
prof: $(BIN)-debug
	./$(BIN)-debug
	gprof $(BIN)-debug gmon.out > perf-analysis.txt

.PHONY: clean
clean:
	rm -f $(OBJ) $(BIN) $(BIN)-debug

.PHONY: distclean
distclean:
	$(MAKE) -C libbloom clean
	$(MAKE) -C sha_digest clean
