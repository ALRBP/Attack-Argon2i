
.PHONY: clean, mrproper

.SUFFIXES:


PRX = ../../


all: $(PRX)$(DBUILD)/argon2i.a

$(PRX)$(DBUILD)/argon2i.a: $(PRX)$(DBUILD)/argon2i.o $(PRX)$(DBUILD)/blake2b.o
	$(AR) -rs $@ $^ $(ARFLAGS)

$(PRX)$(DBUILD)/blake2b.o: blake2/blake2b.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/%.o: %.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

clean:
	$(RM) $(PRX)$(DBUILD)/*

mrproper: clean
	$(RM) $(PRX)$(DOUT)/*
