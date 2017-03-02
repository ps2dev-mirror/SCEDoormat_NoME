SCEDOORMAT_EXE	= bin/SCEDoormat_NoME.exe
SCEDOORMAT_SRC	= public/scedoormat.c public/khn_fs.c public/khn_maths.c
SCEDOORMAT_OBJ	= $(SRC:.c=.o)


all:	\
	$(SCEDOORMAT_EXE)
	rm -f *.o *.s


bin/SCEDoormat_NoME.exe: $(SCEDOORMAT_SRC)
	gcc -o $@ $^


%.o: %.c
	gcc -o $@ -c $< -Wall -O6 -D_WIN32
