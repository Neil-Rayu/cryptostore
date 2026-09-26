// SPDX-License-Identifier: MIT
/*
 * pcie_hello_ctl: exercise a pcie_hello device from userspace.
 *
 *   pcie_hello_ctl [-d /dev/pcie_helloN] <command> [args]
 *
 *   info            device identity, interrupt mode and driver statistics
 *   scratch [VAL]   write VAL (or a set of patterns) to SCRATCH, expect ~VAL
 *   greet           run GREET and print the buffer
 *   upper TEXT      run UPPER on TEXT and print the result
 *   read            print the current buffer (read(2))
 *   write TEXT      store TEXT in the buffer (write(2))
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "pcie_hello_ioctl.h"

static const char *prog = "pcie_hello_ctl";

static const char *irq_mode_name(uint32_t mode)
{
    switch (mode) {
    case PCIE_HELLO_IRQ_INTX: return "INTx";
    case PCIE_HELLO_IRQ_MSI:  return "MSI";
    case PCIE_HELLO_IRQ_MSIX: return "MSI-X";
    default:                  return "none";
    }
}

static int get_info(int fd, struct pcie_hello_info *info)
{
    if (ioctl(fd, PCIE_HELLO_IOC_INFO, info) < 0) {
        fprintf(stderr, "%s: INFO: %s\n", prog, strerror(errno));
        return -1;
    }
    return 0;
}

static int cmd_info(int fd)
{
    struct pcie_hello_info info;

    if (get_info(fd, &info))
        return 1;
    printf("pci device    : %s\n", info.pci_name);
    printf("id            : 0x%08" PRIx32 "\n", info.id);
    printf("hw version    : %" PRIu32 ".%" PRIu32 "\n",
           info.hw_version >> 16, info.hw_version & 0xffff);
    printf("serial        : %" PRIu32 "\n", info.serial);
    printf("buffer size   : %" PRIu32 " bytes\n", info.buf_size);
    printf("status        : 0x%" PRIx32 "\n", info.status);
    printf("interrupt     : %s (irq %" PRIu32 ")\n",
           irq_mode_name(info.irq_mode), info.irq);
    printf("irqs handled  : %" PRIu64 "\n", (uint64_t)info.irq_count);
    printf("commands ok   : %" PRIu64 "\n", (uint64_t)info.cmd_count);
    printf("cmd timeouts  : %" PRIu32 "\n", info.cmd_timeouts);
    printf("resets        : %" PRIu32 "\n", info.resets);
    printf("abi version   : %" PRIu32 "\n", info.abi_version);
    return 0;
}

static int scratch_one(int fd, uint32_t val)
{
    struct pcie_hello_scratch sc = { .in = val };

    if (ioctl(fd, PCIE_HELLO_IOC_SCRATCH, &sc) < 0) {
        fprintf(stderr, "%s: SCRATCH: %s\n", prog, strerror(errno));
        return -1;
    }
    printf("wrote 0x%08" PRIx32 "  read 0x%08" PRIx32 "  %s\n", sc.in, sc.out,
           sc.out == (uint32_t)~val ? "OK" : "MISMATCH (expected ~value)");
    return sc.out == (uint32_t)~val ? 0 : -1;
}

static int cmd_scratch(int fd, int argc, char **argv)
{
    static const uint32_t patterns[] = {
        0x00000000, 0xffffffff, 0x12345678, 0xa5a5a5a5, 0xdeadbeef,
    };
    int fails = 0;
    size_t i;

    if (argc > 0) {
        for (i = 0; i < (size_t)argc; i++)
            fails += scratch_one(fd, strtoul(argv[i], NULL, 0)) != 0;
    } else {
        for (i = 0; i < sizeof(patterns) / sizeof(patterns[0]); i++)
            fails += scratch_one(fd, patterns[i]) != 0;
    }
    return fails ? 1 : 0;
}

static void print_msg(const struct pcie_hello_msg *msg)
{
    printf("%.*s\n", (int)msg->len, (const char *)msg->data);
}

/* Show that a command was completed by an interrupt, not by polling. */
static void print_irq_delta(int fd, uint64_t before)
{
    struct pcie_hello_info info;

    fflush(stdout);     /* keep ordering when both streams are piped */
    if (get_info(fd, &info) == 0)
        fprintf(stderr, "(completed via %s interrupt; irqs %" PRIu64
                " -> %" PRIu64 ")\n", irq_mode_name(info.irq_mode),
                before, (uint64_t)info.irq_count);
}

static int run_msg_ioctl(int fd, unsigned long req, const char *name,
                         struct pcie_hello_msg *msg)
{
    struct pcie_hello_info info;

    if (get_info(fd, &info))
        return 1;
    if (ioctl(fd, req, msg) < 0) {
        fprintf(stderr, "%s: %s: %s\n", prog, name, strerror(errno));
        return 1;
    }
    print_msg(msg);
    print_irq_delta(fd, info.irq_count);
    return 0;
}

static int cmd_greet(int fd)
{
    struct pcie_hello_msg msg;

    memset(&msg, 0, sizeof(msg));
    return run_msg_ioctl(fd, PCIE_HELLO_IOC_GREET, "GREET", &msg);
}

static int cmd_upper(int fd, const char *text)
{
    struct pcie_hello_msg msg;
    size_t len = strlen(text);

    if (len > PCIE_HELLO_MSG_MAX) {
        fprintf(stderr, "%s: text longer than %d bytes\n", prog,
                PCIE_HELLO_MSG_MAX);
        return 1;
    }
    memset(&msg, 0, sizeof(msg));
    msg.len = len;
    memcpy(msg.data, text, len);
    return run_msg_ioctl(fd, PCIE_HELLO_IOC_UPPER, "UPPER", &msg);
}

static int cmd_read(int fd)
{
    char buf[PCIE_HELLO_MSG_MAX];
    ssize_t n, total = 0;

    while ((n = read(fd, buf + total, sizeof(buf) - total)) > 0)
        total += n;
    if (n < 0) {
        fprintf(stderr, "%s: read: %s\n", prog, strerror(errno));
        return 1;
    }
    printf("%.*s\n", (int)total, buf);
    return 0;
}

static int cmd_write(int fd, const char *text)
{
    size_t len = strlen(text);
    ssize_t n = write(fd, text, len);

    if (n < 0) {
        fprintf(stderr, "%s: write: %s\n", prog, strerror(errno));
        return 1;
    }
    if ((size_t)n != len)
        fprintf(stderr, "%s: short write (%zd of %zu bytes)\n", prog, n, len);
    return 0;
}

static void usage(FILE *f)
{
    fprintf(f,
        "usage: %s [-d DEVICE] COMMAND [ARGS]\n"
        "\n"
        "  info            device identity, interrupt mode, statistics\n"
        "  scratch [VAL]   scratch register test (device returns ~VAL)\n"
        "  greet           run GREET and print the buffer\n"
        "  upper TEXT      uppercase TEXT on the device\n"
        "  read            print the buffer contents\n"
        "  write TEXT      store TEXT in the buffer\n"
        "\n"
        "DEVICE defaults to /dev/pcie_hello0.\n", prog);
}

int main(int argc, char **argv)
{
    const char *dev = "/dev/pcie_hello0";
    const char *cmd;
    int opt, fd, ret;

    while ((opt = getopt(argc, argv, "d:h")) != -1) {
        switch (opt) {
        case 'd':
            dev = optarg;
            break;
        case 'h':
            usage(stdout);
            return 0;
        default:
            usage(stderr);
            return 2;
        }
    }
    if (optind >= argc) {
        usage(stderr);
        return 2;
    }
    cmd = argv[optind++];
    argc -= optind;
    argv += optind;

    fd = open(dev, O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "%s: %s: %s\n", prog, dev, strerror(errno));
        return 1;
    }

    if (!strcmp(cmd, "info")) {
        ret = cmd_info(fd);
    } else if (!strcmp(cmd, "scratch")) {
        ret = cmd_scratch(fd, argc, argv);
    } else if (!strcmp(cmd, "greet")) {
        ret = cmd_greet(fd);
    } else if (!strcmp(cmd, "upper") && argc == 1) {
        ret = cmd_upper(fd, argv[0]);
    } else if (!strcmp(cmd, "read")) {
        ret = cmd_read(fd);
    } else if (!strcmp(cmd, "write") && argc == 1) {
        ret = cmd_write(fd, argv[0]);
    } else {
        usage(stderr);
        ret = 2;
    }

    close(fd);
    return ret;
}
