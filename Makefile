# Set up basic variables:
CC = c++
CFLAGS = -O2 -std=c++17 -I.
LDFLAGS = -Wl,-rpath -Wl,libs

# List of sources:
SOURCES =  main.cpp httplib/httplib.cc fmt/format.cc
OBJECTS = main.o httplib/httplib.o fmt/format.o

# Name of executable target:
EXECUTABLE = bin/Release/cpp-kalkan

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
	$(CC) -o $@ $(OBJECTS) $(LDFLAGS)

.cpp.o:
	$(CC) $(CFLAGS) -c $< -o $@

.cc.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJECTS) $(EXECUTABLE)
