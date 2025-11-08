#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <string.h>
#include <stdint.h>
#include <linux/kvm.h>
#include <getopt.h>
#include <stdbool.h>
#include <pthread.h>

#define MAX_THREADS 10
#define MAX_FILES 128
#define MAX_PATH 256

#define FILE_READ 0x01
#define FILE_WRITE 0x02

#define MEM_SIZE (2u * 1024u * 1024u)
#define GUEST_START_ADDR 0x0000

#define PDE64_PRESENT (1u << 0)
#define PDE64_RW (1u << 1)
#define PDE64_USER (1u << 2)
#define PDE64_PS (1u << 7)

#define CR0_PE (1u << 0)
#define CR0_PG (1u << 31)
#define CR4_PAE (1u << 5)

#define EFER_LME (1u << 8)
#define EFER_LMA (1u << 10)

struct vm {
	int kvm_fd;
	int vm_fd;
	int vcpu_fd;
	char *mem;
	size_t mem_size;
	struct kvm_run *run;
	int run_mmap_size;
};

struct guest_file {
    char path[MAX_PATH];
    FILE *f;
    int flags;
    int shared;
};

struct vm_file_table {
    struct guest_file files[MAX_FILES];
    int count;
};

int vm_init(struct vm *v, size_t mem_size)
{
	struct kvm_userspace_memory_region region;	

	memset(v, 0, sizeof(*v));
	v->kvm_fd = v->vm_fd = v->vcpu_fd = -1;
	v->mem = MAP_FAILED;
	v->run = MAP_FAILED;
	v->run_mmap_size = 0;
	v->mem_size = mem_size;

	v->kvm_fd = open("/dev/kvm", O_RDWR);
	if (v->kvm_fd < 0) {
		perror("open /dev/kvm");
		return -1;
	}

    int api = ioctl(v->kvm_fd, KVM_GET_API_VERSION, 0);
    if (api != KVM_API_VERSION) {
        printf("KVM API mismatch: kernel=%d headers=%d\n", api, KVM_API_VERSION);
        return -1;
    }

	v->vm_fd = ioctl(v->kvm_fd, KVM_CREATE_VM, 0);
	if (v->vm_fd < 0) {
		perror("KVM_CREATE_VM");
		return -1;
	}

	v->mem = mmap(NULL, mem_size, PROT_READ | PROT_WRITE,
		   MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	if (v->mem == MAP_FAILED) {
		perror("mmap mem");
		return -1;
	}

	region.slot = 0;
	region.flags = 0;
	region.guest_phys_addr = 0;
	region.memory_size = v->mem_size;
	region.userspace_addr = (uintptr_t)v->mem;
    if (ioctl(v->vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
		perror("KVM_SET_USER_MEMORY_REGION");
        return -1;
	}

	v->vcpu_fd = ioctl(v->vm_fd, KVM_CREATE_VCPU, 0);
    if (v->vcpu_fd < 0) {
		perror("KVM_CREATE_VCPU");
        return -1;
	}

	v->run_mmap_size = ioctl(v->kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
    if (v->run_mmap_size <= 0) {
		perror("KVM_GET_VCPU_MMAP_SIZE");
		return -1;
	}

	v->run = mmap(NULL, v->run_mmap_size, PROT_READ | PROT_WRITE,
			     MAP_SHARED, v->vcpu_fd, 0);
	if (v->run == MAP_FAILED) {
		perror("mmap kvm_run");
		return -1;
	}

	return 0;
}

void vm_destroy(struct vm *v) {
    
	if (v->run && v->run != MAP_FAILED) {
		munmap(v->run, (size_t)v->run_mmap_size);
		v->run = MAP_FAILED;
	}

	if(v->mem && v->mem != MAP_FAILED) {
		munmap(v->mem, v->mem_size);
		v->mem = MAP_FAILED;
	}

	if (v->vcpu_fd >= 0) {
		close(v->vcpu_fd);
		v->vcpu_fd = -1;
	}

	if (v->vm_fd >= 0) {
		close(v->vm_fd);
		v->vm_fd = -1;
	}

	if (v->kvm_fd >= 0) {
		close(v->kvm_fd);
		v->kvm_fd = -1;
	}
}

static void setup_segments_64(struct kvm_sregs *sregs)
{
	struct kvm_segment code = {
		.base = 0,
		.limit = 0xffffffff,
		.present = 1,
		.type = 11,
		.dpl = 0, 
		.db = 0,
		.s = 1, 
		.l = 1, 
		.g = 1,
	};
	struct kvm_segment data = code;
	data.type = 3; 
	data.l = 0;

	sregs->cs = code;
	sregs->ds = sregs->es = sregs->fs = sregs->gs = sregs->ss = data;
}

static void setup_long_mode(struct vm *v, struct kvm_sregs *sregs, uint64_t page_size, size_t mem_size)
{
	uint64_t pml4_addr = 0x1000; 
	uint64_t *pml4 = (void *)(v->mem + pml4_addr);

	uint64_t pdpt_addr = 0x2000;
	uint64_t *pdpt = (void *)(v->mem + pdpt_addr);

	uint64_t pd_addr = 0x3000;
	uint64_t *pd = (void *)(v->mem + pd_addr);

	uint64_t pt_addr = 0x4000;
	uint64_t *pt = (void *)(v->mem + pt_addr);

    pml4[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pdpt_addr;
    pdpt[0] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pd_addr;

    if (page_size == 0x1000) {

        size_t num_pd = mem_size / page_size / 512;

        for (size_t i = 0; i < num_pd; i++) {
            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | pt_addr;
            for (size_t j = 0; j < 512; j++) {
                pt[j] = (j * 0x1000) | PDE64_PRESENT | PDE64_RW | PDE64_USER;
                if (pt[j] > mem_size) break; 
            }
            
            pt_addr += 0x1000;
        }

        pt_addr = 0x4000;
        pt[0] = GUEST_START_ADDR | PDE64_PRESENT | PDE64_RW | PDE64_USER;

    } else if (page_size == 0x200000) {
        size_t num_entries = mem_size / page_size; 
        for (size_t i = 0; i < num_entries; i++) {
            pd[i] = PDE64_PRESENT | PDE64_RW | PDE64_USER | PDE64_PS;
        }
    }

	sregs->cr3  = pml4_addr; 
	sregs->cr4  = CR4_PAE; 
	sregs->cr0  = CR0_PE | CR0_PG; 
	sregs->efer = EFER_LME | EFER_LMA; 

	setup_segments_64(sregs);
}

int load_guest_image(struct vm *v, const char *image_path, uint64_t load_addr) {

	FILE *f = fopen(image_path, "rb");
	if (!f) {
		perror("Failed to open guest image");
		return -1;
	}

	if (fseek(f, 0, SEEK_END) < 0) {
		perror("Failed to seek to end of guest image");
		fclose(f);
		return -1;
	}

	long fsz = ftell(f);
	if (fsz < 0) {
		perror("Failed to get size of guest image");
		fclose(f);
		return -1;
	}
	rewind(f);

	if((uint64_t)fsz > v->mem_size - load_addr) {
		printf("Guest image is too large for the VM memory\n");
		fclose(f);
		return -1;
	}

	if (fread((uint8_t*)v->mem + load_addr, 1, (size_t)fsz, f) != (size_t)fsz) {
		perror("Failed to read guest image");
		fclose(f);
		return -1;
	}
	fclose(f);

	return 0;
}

int guest_file_open(struct vm_file_table *tbl, const char *path, int flags, int shared)
{
    if (tbl->count >= MAX_FILES) return -1;

    struct guest_file *gf = &tbl->files[tbl->count];
    strncpy(gf->path, path, MAX_PATH-1);
    gf->path[MAX_PATH-1] = 0;
    gf->flags = flags;
    gf->shared = shared;

    const char *mode = (flags & FILE_WRITE) ? "ab+" : "rb";
    gf->f = fopen(path, mode);
    if (!gf->f) return -1;

    return tbl->count++;
}

ssize_t guest_file_read(struct vm_file_table *tbl, int handle, void *buf, size_t size)
{
    if (handle >= tbl->count) return -1;
    struct guest_file *gf = &tbl->files[handle];
    if (!(gf->flags & FILE_READ)) return -1;
    return fread(buf, 1, size, gf->f);
}

ssize_t guest_file_write(struct vm_file_table *tbl, int handle, const void *buf, size_t size)
{
    if (handle >= tbl->count) return -1;
    struct guest_file *gf = &tbl->files[handle];
    if (!(gf->flags & FILE_WRITE)) return -1;

    if (gf->shared) {
        char local_path[MAX_PATH];
        if (snprintf(local_path, MAX_PATH, "%s_vm%p", gf->path, (void*)tbl) >= MAX_PATH)
            fprintf(stderr, "Warning: truncated path: %s\n", gf->path);
        FILE *f = fopen(local_path, "ab+");
        if (!f) return -1;
        gf->f = f;
        gf->shared = 0;
    }
    return fwrite(buf, 1, size, gf->f);
}

int guest_file_close(struct vm_file_table *tbl, int handle)
{
    if (handle >= tbl->count) return -1;
    struct guest_file *gf = &tbl->files[handle];
    if (gf->f) fclose(gf->f);
    gf->f = NULL;
    return 0;
}

struct input_params {
    size_t mem_size; 
    uint64_t page_size;
	char *guest_images[MAX_THREADS];
    int guest_count;
    char *guest_files[MAX_FILES];
    int file_count;
    bool mem_set;
    bool page_set;
    int i;
};

struct thread_arg {
    struct input_params *params;
    int i;
};

void *run_vm(void *arg) {
    uint8_t io_buffer[512];
    size_t io_expected_len = 0;
    size_t io_received = 0;
    int awaiting_command = 0;
    int last_handle = -1;
    uint8_t last_cmd = 0;
    uint8_t last_data[256];
    ssize_t last_result = 0;

    memset(io_buffer, 0, sizeof(io_buffer));
    memset(last_data, 0, sizeof(last_data));

    struct thread_arg *targ = (struct thread_arg *)arg;
    struct input_params *params = targ->params;
    int i = targ->i;

    char *guest_image = params->guest_images[i];
    size_t mem_size = params->mem_size;
    uint64_t page_size = params->page_size;

    struct vm v;
    struct kvm_sregs sregs;
    struct kvm_regs regs;
    int stop = 0;
    int ret = 0;

    struct vm_file_table files_tbl;
    memset(&files_tbl, 0, sizeof(files_tbl));

    for (int i = 0; i < params->file_count; i++) {
        guest_file_open(&files_tbl, params->guest_files[i], FILE_READ|FILE_WRITE, 1);
        last_handle++;
    }

    if (vm_init(&v, mem_size)) {
        printf("Failed to init the VM\n");
        pthread_exit(NULL);
    }

    if (ioctl(v.vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
        perror("KVM_GET_SREGS");
        vm_destroy(&v);
        pthread_exit(NULL);
    }

    setup_long_mode(&v, &sregs, page_size, mem_size);

    if (ioctl(v.vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
        perror("KVM_SET_SREGS");
        vm_destroy(&v);
        pthread_exit(NULL);
    }

    if (load_guest_image(&v, guest_image, GUEST_START_ADDR) < 0) {
        printf("Failed to load guest image\n");
        vm_destroy(&v);
        pthread_exit(NULL);
    }

    memset(&regs, 0, sizeof(regs));
    regs.rflags = 0x2;
    
    regs.rip = 0; 
    regs.rsp = 2 << 20; 

    if (ioctl(v.vcpu_fd, KVM_SET_REGS, &regs) < 0) {
        perror("KVM_SET_REGS");
        pthread_exit(NULL);
    }

    while (stop == 0) {
        ret = ioctl(v.vcpu_fd, KVM_RUN, 0);
        if (ret == -1) {
            printf("KVM_RUN failed\n");
            vm_destroy(&v);
            pthread_exit(NULL);
        }

        switch (v.run->exit_reason) {
            case KVM_EXIT_IO:
                if (v.run->io.direction == KVM_EXIT_IO_OUT && v.run->io.port == 0xE9) {
                    // standardni debug izlaz
                    char *p = (char *)v.run;
                    printf("%c", *(p + v.run->io.data_offset));
                }

                else if (v.run->io.direction == KVM_EXIT_IO_OUT && v.run->io.port == 0x0278) {
                    uint8_t *data = (uint8_t *)v.run + v.run->io.data_offset;
                    uint8_t val = *data;

                    // prvi bajt označava dužinu paketa
                    if (!awaiting_command) {
                        io_expected_len = val;
                        io_received = 0;
                        awaiting_command = 1;
                    } else {
                        // ubaci bajt u buffer
                        io_buffer[io_received++] = val;

                        if (io_received >= io_expected_len) {
                            // kompletna poruka primljena
                            uint8_t cmd = io_buffer[0];
                            last_cmd = cmd;

                            switch (cmd) {
                                case 0x01: { // fopen
                                    const char *path = (const char *)(io_buffer + 1);
                                    int flags = io_buffer[strlen(path) + 2];
                                    int shared = io_buffer[strlen(path) + 3];
                                    printf("[HV] Guest requests OPEN('%s', flags=%d, shared=%d)\n", path, flags, shared);

                                    int handle = guest_file_open(&files_tbl, path, flags, shared);
                                    last_handle = handle;
                                    break;
                                }

                                case 0x02: { // READ
                                    int handle = io_buffer[1];
                                    size_t size = *(size_t *)(io_buffer + 2);

                                    uint8_t tmp_buf[256];
                                    ssize_t n = guest_file_read(&files_tbl, handle, tmp_buf, size);
                                    if (n > 0) {
                                        memcpy(last_data, tmp_buf, n);
                                        last_result = n;
                                    } else {
                                        last_result = 0;
                                    }

                                    printf("[HV] fread(handle=%d, size=%zu) -> %zd\n", handle, size, n);
                                    break;
                                }

                                case 0x03: { // fwrite
                                    int handle = io_buffer[1];
                                    size_t size = *(size_t *)(io_buffer + 2);
                                    ssize_t n = guest_file_write(&files_tbl, handle, io_buffer + 10, size);
                                    last_result = n;
                                    printf("[HV] fwrite(handle=%d, size=%zu) -> %zd\n", handle, size, n);
                                    break;
                                }

                                case 0x04: { // fclose
                                    int handle = io_buffer[1];
                                    guest_file_close(&files_tbl, handle);
                                    last_result = 0;
                                    printf("[HV] fclose(handle=%d)\n", handle);
                                    break;
                                }

                                default:
                                    printf("[HV] Nepoznata komanda: 0x%02X\n", cmd);
                                    break;
                            }

                            awaiting_command = 0; // resetuj stanje
                        }
                    }
                }

                else if (v.run->io.direction == KVM_EXIT_IO_IN && v.run->io.port == 0x0278) {
                    uint8_t *ret_data = (uint8_t *)v.run + v.run->io.data_offset;

                    switch (last_cmd) {
                        case 0x01: // fopen
                            *ret_data = (uint8_t)last_handle;
                            break;

                        case 0x02: // fread
                            static size_t send_offset = 0;

                            if (send_offset < last_result) {
                                uint8_t *ret = (uint8_t *)v.run + v.run->io.data_offset;
                                *ret_data = last_data[send_offset++];
                            } else {
                                // kad sve pošalje, resetuj
                                send_offset = 0;
                                *ret_data = 0; // kraj
                            }

                            break;

                        case 0x03: // fwrite
                        case 0x04: // fclose
                            memcpy(ret_data, &last_result, sizeof(ssize_t));
                            break;

                        default:
                            *ret_data = 0xFF;
                            break;
                    }
                }

                continue;

            case KVM_EXIT_HLT:
                printf("KVM_EXIT_HLT\n");
                stop = 1;
                break;

            case KVM_EXIT_SHUTDOWN:
                printf("Shutdown\n");
                stop = 1;
                break;

            default:
                printf("Default - exit reason: %d\n", v.run->exit_reason);
                break;
        }
    }

    vm_destroy(&v);

    free(targ);
    pthread_exit(NULL);

}

struct input_params *get_input_params(int argc, char *argv[]) {

    struct input_params *params = malloc(sizeof(struct input_params));

    if (!params) {
        perror("malloc failed");
        exit(1);
    }

    memset(params, 0, sizeof(*params));

    for (int i = 1; i < argc; i++) {
		if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--memory") == 0) {
			if (i + 1 == argc || argv[i + 1][0] == '-') {
			    fprintf(stderr, "Enter memory size.\n");
				exit(1);
			} 
			else {
				if (strcmp(argv[i + 1], "2") == 0 || strcmp(argv[i + 1], "4") == 0 || strcmp(argv[i + 1], "8") == 0) {
					params->mem_size = atoi(argv[i + 1]) * 1024 * 1024;
					params->mem_set = true;
				}
				else {
					fprintf(stderr, "Invalid memory size: %s\n", argv[i]);
                    exit(1);
				}
			}
		} 
		else if (strcmp(argv[i], "-p") == 0 || strcmp(argv[i], "--page") == 0) {
			if (i + 1 == argc || argv[i + 1][0] == '-') {
			    fprintf(stderr, "Enter page size.\n");
				exit(1);
			} 
			else {
                if (strcmp(argv[i + 1], "4") == 0) {
                    params->page_size = 0x1000; 
                    params->page_set = true;
                } else if (strcmp(argv[i + 1], "2") == 0) {
                    params->page_size = 0x200000;
                    params->page_set = true;
                } else {
                    fprintf(stderr, "Invalid page size: %s\n", argv[i + 1]);
                    exit(1);
                }
			}
		} 
		else if (strcmp(argv[i], "-g") == 0 || strcmp(argv[i], "--guest") == 0) {
			if (i + 1 == argc || argv[i + 1][0] == '-') {
			    fprintf(stderr, "Enter guest image(s).\n");
				exit(1);
			} 
			else {
				while (i + 1 < argc && argv[i + 1][0] != '-') {
					if (params->guest_count < MAX_THREADS) params->guest_images[params->guest_count++] = argv[i++ + 1];
					else {
						fprintf(stderr, "Maximum number of threads is: %d", MAX_THREADS);
						exit(1);
					}
				}
			}
		}
        else if (strcmp(argv[i], "-f") == 0 || strcmp(argv[i], "--file") == 0) {
			if (i + 1 == argc || argv[i + 1][0] == '-') {
			    fprintf(stderr, "Enter file(s).\n");
				exit(1);
			} 
			else {
				while (i + 1 < argc && argv[i + 1][0] != '-') {
					if (params->file_count < MAX_FILES) params->guest_files[params->file_count++] = argv[i++ + 1];
					else {
						fprintf(stderr, "Maximum number of files is: %d", MAX_FILES);
						exit(1);
					}
				}
			}
		}
	}

	if(!params->mem_set || !params->page_set || params->guest_count == 0) {
		fprintf(stderr, "All parameters --memory, --page, and --guest are required.\n");
		exit(1);
	}

    return params;
}

int main(int argc, char *argv[])
{
    struct input_params *params = get_input_params(argc, argv);
    
    pthread_t threads[params->guest_count];

    for (int i = 0; i < params->guest_count; i++) {
        struct thread_arg *targ = malloc(sizeof(struct thread_arg));
        targ->params = params;
        targ->i = i;
        if (pthread_create(&threads[i], NULL, run_vm, (void *)targ) != 0) {
            perror("Ne može da se stvori nit");
            return 1;
        }
    }

    for (int i = 0; i < params->guest_count; i++) {
        pthread_join(threads[i], NULL);
    }	

}
