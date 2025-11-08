GUEST_DIR = ../Guest
GUEST1_IMG = $(GUEST_DIR)/guest1.img
GUEST2_IMG = $(GUEST_DIR)/guest2.img
GUEST3_IMG = $(GUEST_DIR)/guest3.img
GUEST4_IMG = $(GUEST_DIR)/guest4.img

.PHONY: all clean

# Podrazumevana meta – builduj sve i pokreni
all: mini_hypervisor $(GUEST1_IMG) $(GUEST2_IMG) $(GUEST3_IMG) $(GUEST4_IMG)
	./mini_hypervisor -p 4 --file file1.txt -m 4 -g $(GUEST3_IMG) $(GUEST4_IMG)

# Kompajliraj hypervisor
mini_hypervisor: mini_hypervisor.c
	gcc mini_hypervisor.c -o $@ -lpthread

# Builduj guest1.img i guest2.img pozivom make u Guest folderu
$(GUEST1_IMG) $(GUEST2_IMG) $(GUEST3_IMG) $(GUEST4_IMG):
	$(MAKE) -C $(GUEST_DIR)

# Clean
clean:
	rm -f mini_hypervisor
	$(MAKE) -C $(GUEST_DIR) clean
