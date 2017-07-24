
.PHONY: clean, mrproper

.SUFFIXES:


PRX = ../../


all: $(PRX)$(DBUILD)/attack.a

$(PRX)$(DBUILD)/attack.a: $(PRX)$(DBUILD)/attack.o $(PRX)$(DBUILD)/solve_solve.o  $(PRX)$(DBUILD)/solve_params.o $(PRX)$(DBUILD)/solve_post.o $(PRX)$(DBUILD)/solve_parallel.o $(PRX)$(DBUILD)/graph_gen.o $(PRX)$(DBUILD)/graph_lin.o $(PRX)$(DBUILD)/inst.o $(PRX)$(DBUILD)/run_run.o $(PRX)$(DBUILD)/run_parallel.o
	$(AR) -q $@ $^ $(ARFLAGS)

$(PRX)$(DBUILD)/solve_solve.o: solve/solve.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/solve_params.o: solve/params.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/solve_post.o: solve/post.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/solve_parallel.o: solve/parallel.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/graph_gen.o: graph/gen.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/graph_lin.o: graph/lin.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/inst.o: inst/inst.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/run_run.o: run/run.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/run_parallel.o: run/parallel.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

$(PRX)$(DBUILD)/%.o: %.c
	$(CC) -c -fPIC $^ -o $@ $(CFLAGS)

clean:
	$(RM) $(PRX)$(DBUILD)/*

mrproper: clean
	$(RM) $(PRX)$(DOUT)/*
