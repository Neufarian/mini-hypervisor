mini_hypervisor: mini_hypervisor.c
	gcc mini_hypervisor.c -o mini_hypervisor

clean:
	rm -f mini_hypervisor

run: mini_hypervisor
	./mini_hypervisor -p 4 -m 8 -g ../Guest/guest1.img