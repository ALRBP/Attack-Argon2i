
.PHONY: clean, mrproper

.SUFFIXES:


DEBUG = no
PP = no

export AR = ar
export RM = rm -rf
export MK = mkdir
export CD = cd
ifeq ($(PP),yes)
	export CC = g++
	export BCFLAGS = -W -Wall -Werror -std=c++14 -Wc++14-compat
	export LDFLAGS=
	export ARFLAGS =
else
	export CC = gcc
	export BCFLAGS = -W -Wall -Werror -std=c11 -Wc99-c11-compat
	export LDFLAGS =
	export ARFLAGS = 
endif
ifeq ($(DEBUG),yes)
	export PCFLAGS = -g $(BCFLAGS)
else
	export PCFLAGS = $(BCFLAGS) -O3
endif
export CFLAGS = $(PCFLAGS) -lpthread -lm
export BIN = attack
export LIB = libaargon
export DBUILD = build
export DOUT = output
export LPATH = $(DOUT)
export PRG = ../
PRX = ../


all: $(BIN) $(LIB)

$(BIN): $(PRX)$(DOUT)/$(BIN)

$(LIB): $(PRX)$(DOUT)/$(LIB).so
	
$(PRX)$(DOUT)/$(LIB).so: $(PRX)$(DBUILD)/argon2i.a $(PRX)$(DBUILD)/attack.a
	$(CC) -Wl,--whole-archive $^ -Wl,-no-whole-archive -shared -fPIC -o $@ $(CFLAGS)

$(PRX)$(DOUT)/$(BIN): $(PRX)$(DBUILD)/main.o
	$(MAKE) $(LIB)
	$(CC) $^ -fPIC -L $(PRX)$(LPATH) -Wl,-rpath=$(PRX)$(LPATH) -laargon -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/argon2i.a:
	$(CD) argon2 && $(MAKE) $(PRG)$@

$(PRX)$(DBUILD)/attack.a:
	$(CD) attack && $(MAKE) $(PRG)$@

$(PRX)$(DBUILD)/%.o: %.c
	$(CC) -c $^ -o $@ $(CFLAGS)

clean:
	$(RM) $(PRX)$(DBUILD)/*

mrproper: clean
	$(RM) $(PRX)$(DOUT)/*
