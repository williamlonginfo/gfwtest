C++ = g++

ifndef os
	os = LINUX
endif
CCFLAGS= -DSabayon -DLINUX
LDFLAGS=-lpcap

SRC= $(shell ls *.cpp)
OBJS= $(SRC:%.cpp=%.o)
DIR = $(shell pwd)
Target=gfwtest
all: $(Target)

$(Target):$(OBJS)
	$(C++) -o $@ $^  $(LDFLAGS)

%.o: %.cpp
	$(C++) $(CCFLAGS) $< -c

clean:
	rm -f *.o
	rm -f $(Target)

install:
	export PATH=$(DIR):$$PATH
