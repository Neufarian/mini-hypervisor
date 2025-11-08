CC = gcc
LD = ld

CFLAGS = -m64 -ffreestanding -fno-pic
LDFLAGS = -T guest.ld

# Default target: build both images
all: guest1.img guest2.img guest3.img guest4.img

# guest1.img: compile + link
guest1.img: guest1.o
	$(LD) $(LDFLAGS) -o $@ $<

guest1.o: guest1.c
	$(CC) $(CFLAGS) -c -o $@ $<

# guest2.img: compile + link
guest2.img: guest2.o
	$(LD) $(LDFLAGS) -o $@ $<

guest2.o: guest2.c
	$(CC) $(CFLAGS) -c -o $@ $<

# guest3.img: compile + link
guest3.img: guest3.o
	$(LD) $(LDFLAGS) -o $@ $<

guest3.o: guest3.c
	$(CC) $(CFLAGS) -c -o $@ $<

# guest4.img: compile + link
guest4.img: guest4.o
	$(LD) $(LDFLAGS) -o $@ $<

guest4.o: guest4.c
	$(CC) $(CFLAGS) -c -o $@ $<

# Clean
clean:
	rm -f guest1.o guest1.img guest2.o guest2.img guest3.o guest3.img guest4.o guest4.img
