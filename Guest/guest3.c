#include <stdint.h>
#include <string.h>
#include <unistd.h>

#define HV_IO_PORT 0x0278

// ---------- helper funkcije ----------

static inline void outb(uint16_t port, uint8_t val) {
    asm volatile("outb %0,%1" : : "a"(val), "Nd"(port));
}

static inline uint8_t inb(uint16_t port) {
    uint8_t ret;
    asm volatile("inb %1,%0" : "=a"(ret) : "Nd"(port));
    return ret;
}

void hv_send_buffer(const void *buf, size_t len) {
    outb(HV_IO_PORT, (uint8_t)len); // pošalji dužinu paketa
    const uint8_t *b = buf;
    for (size_t i = 0; i < len; i++) {
        outb(HV_IO_PORT, b[i]);
    }
}

uint8_t hv_receive_byte(void) {
    return inb(HV_IO_PORT);
}

size_t strlen(const char *s) {
    size_t n = 0;
    while (*s++) n++;
    return n;
}

char *strcpy(char *dest, const char *src) {
    char *d = dest;
    while ((*d++ = *src++));
    return dest;
}

void *memcpy(void *dest, const void *src, size_t n) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    while (n--) *d++ = *s++;
    return dest;
}

// ---------- sistem fajl interfejs ----------

typedef uint32_t file_handle;
#define FILE_READ  0x01
#define FILE_WRITE 0x02

// ---------- fopen ----------
file_handle hv_fopen(const char *path, int flags) {
    uint8_t buf[256] = { 0 };
    buf[0] = 0x01; // cmd = open
    strcpy((char *)(buf + 1), path);
    buf[strlen(path) + 2] = flags;
    buf[strlen(path) + 3] = 1; // shared = true

    hv_send_buffer(buf, strlen(path) + 4);
    return hv_receive_byte(); // handle iz hipervizora
}

// ---------- fread ----------
ssize_t hv_fread(file_handle fh, void *buf, size_t size) {
    uint8_t data[256] = {0};
    data[0] = 0x02; // read
    data[1] = fh;
    *(size_t *)(data + 2) = size;

    hv_send_buffer(data, 10); // pošalji zahtev

    // sad preuzmi podatke iz IN porta
    for (size_t i = 0; i < size; i++)
        ((uint8_t *)buf)[i] = inb(HV_IO_PORT);

    return size; 
}


// ---------- fwrite ----------
ssize_t hv_fwrite(file_handle fh, const void *buf, size_t size) {
    uint8_t packet[256] = { 0 };
    packet[0] = 0x03;           // cmd = write
    packet[1] = fh;             // handle
    *(size_t *)(packet + 2) = size;
    memcpy(packet + 10, buf, size);

    hv_send_buffer(packet, 10 + size);

    // očekuj broj upisanih bajtova
    uint8_t res_buf[sizeof(ssize_t)] = {0};
    for (size_t i = 0; i < sizeof(ssize_t); i++)
        res_buf[i] = hv_receive_byte();

    return *(ssize_t *)res_buf;
}

// ---------- fclose ----------
int hv_fclose(file_handle fh) {
    uint8_t packet[4] = { 0x04, fh, 0, 0 };
    hv_send_buffer(packet, 2);
    return 0;
}


void
__attribute__((noreturn))
__attribute__((section(".start")))
_start(void) {

	/*
		INSERT CODE BELOW THIS LINE
	*/

    file_handle f1 = hv_fopen("file1.txt", FILE_WRITE|FILE_READ);
    file_handle f2 = hv_fopen("file2.txt", FILE_WRITE|FILE_READ);

    // ---------testing write---------
    const char *msg = "Hello from guest3!";
    hv_fwrite(f2, msg, strlen(msg));

    // ---------testing read---------
    char buf[64];
    ssize_t n = hv_fread(f1, buf, 10);
    for (ssize_t i = 0; i < n; i++) outb(0xE9, buf[i]);

    hv_fclose(f1);
    hv_fclose(f2);

	/*
		INSERT CODE ABOVE THIS LINE
	*/

	for (;;)
		asm("hlt");
}