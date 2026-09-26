// SPDX-License-Identifier: MIT
/*
 * cryptoctl: manage pcie-cryptostore devices from the guest.
 *
 *   cryptoctl [-d CTL] [-r RECOVERY] COMMAND
 *
 * Secrets are never taken from the command line (SR-13). They are read from
 * the terminal with echo off, or from stdin (one per line) when stdin is not
 * a terminal. The process locks its memory, disables core dumps and wipes
 * every password buffer after use.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <termios.h>
#include <unistd.h>

#include "cryptostore_regs.h"
#include "cryptostore_ioctl.h"

#define MIN_PASSWORD_LEN    8       /* O9: a policy floor, not a guarantee */

static const char *prog = "cryptoctl";
static const char *ctl_path = "/dev/cryptostore-ctl0";
static const char *rec_path = "/dev/cryptorecovery0";

static const char *state_name(uint32_t s)
{
    switch (s) {
    case CS_STATE_UNFORMATTED: return "UNFORMATTED";
    case CS_STATE_LOCKED:      return "LOCKED";
    case CS_STATE_UNLOCKED:    return "UNLOCKED";
    case CS_STATE_RECOVERED:   return "RECOVERED (set a new password: cryptoctl passwd)";
    case CS_STATE_LOCKED_OUT:  return "LOCKED_OUT (too many failures: cryptoctl recover)";
    case CS_STATE_ERROR:       return "ERROR (image rejected or tampered with)";
    default:                   return "unknown";
    }
}

static const char *result_text(uint32_t r)
{
    switch (r) {
    case CS_OK:                  return "OK";
    case CS_ERR_INVALID_CMD:     return "the device does not know this command";
    case CS_ERR_STATE:           return "not possible in the device's current state";
    case CS_ERR_LOCKED:          return "the device is locked";
    case CS_ERR_AUTH:            return "wrong password";
    case CS_ERR_BACKOFF:         return "too many recent failures; wait before trying again";
    case CS_ERR_LOCKED_OUT:      return "locked out after too many failures; use 'cryptoctl recover'";
    case CS_ERR_INTEGRITY:       return "password correct, but the image header was tampered with; "
                                        "the device refuses it";
    case CS_ERR_NO_RECOVERY:     return "no recovery device or no recovery key for this image";
    case CS_ERR_NOT_ARMED:       return "recovery device not armed (guest arm and host presence "
                                        "are both needed, once per boot)";
    case CS_ERR_RANGE:           return "invalid length or range (password must be 1-128 bytes; "
                                        "the image may be too small to format)";
    case CS_ERR_IO:              return "backing file I/O error";
    case CS_ERR_PASSWD_REQUIRED: return "recovered: set a new password first ('cryptoctl passwd')";
    case CS_ERR_FAULT:           return "fault detected; the device zeroized its keys and locked out";
    case CS_ERR_UNSUPPORTED:     return "not supported by this device version";
    default:                     return "unknown result";
    }
}

static void harden_process(void)
{
    struct rlimit no_core = { 0, 0 };

    setrlimit(RLIMIT_CORE, &no_core);
    prctl(PR_SET_DUMPABLE, 0, 0, 0, 0);
    if (mlockall(MCL_CURRENT | MCL_FUTURE) != 0) {
        fprintf(stderr, "%s: warning: mlockall failed (%s); passwords could be swapped out\n",
                prog, strerror(errno));
    }
}

/*
 * Read one line into @buf without stdio buffering. From the terminal with
 * echo off when stdin is a tty, otherwise from stdin. Returns the length,
 * or -1. The newline is not stored.
 */
static int read_secret(const char *prompt, uint8_t *buf, size_t cap)
{
    bool tty = isatty(STDIN_FILENO);
    int fd = STDIN_FILENO;
    struct termios old, quiet;
    size_t n = 0;
    char ch;

    if (tty) {
        fd = open("/dev/tty", O_RDWR | O_CLOEXEC);
        if (fd < 0) {
            return -1;
        }
        if (write(fd, prompt, strlen(prompt)) < 0) { /* best effort */ }
        tcgetattr(fd, &old);
        quiet = old;
        quiet.c_lflag &= ~(ECHO | ECHONL);
        tcsetattr(fd, TCSAFLUSH, &quiet);
    }
    for (;;) {
        ssize_t r = read(fd, &ch, 1);

        if (r <= 0 || ch == '\n') {
            break;
        }
        if (n < cap) {
            buf[n] = (uint8_t)ch;
        }
        n++;
    }
    if (tty) {
        tcsetattr(fd, TCSAFLUSH, &old);
        if (write(fd, "\n", 1) < 0) { /* best effort */ }
        close(fd);
    }
    ch = 0;
    if (n > cap) {
        explicit_bzero(buf, cap);
        fprintf(stderr, "%s: password longer than %zu bytes\n", prog, cap);
        return -1;
    }
    return (int)n;
}

static int get_password(struct cryptostore_password *pw, const char *prompt)
{
    int n = read_secret(prompt, pw->data, sizeof(pw->data));

    if (n <= 0) {
        explicit_bzero(pw, sizeof(*pw));
        if (n == 0) {
            fprintf(stderr, "%s: empty password\n", prog);
        }
        return -1;
    }
    pw->len = (uint32_t)n;
    return 0;
}

/* A new password, entered twice, with a minimum length (O9). */
static int get_new_password(struct cryptostore_password *pw, const char *what)
{
    struct cryptostore_password again;
    char prompt[96];
    int ret = -1;

    memset(&again, 0, sizeof(again));
    snprintf(prompt, sizeof(prompt), "%s: ", what);
    if (get_password(pw, prompt) < 0) {
        goto out;
    }
    if (pw->len < MIN_PASSWORD_LEN) {
        fprintf(stderr, "%s: use at least %d characters\n", prog, MIN_PASSWORD_LEN);
        goto out;
    }
    snprintf(prompt, sizeof(prompt), "Repeat %s: ", what);
    if (get_password(&again, prompt) < 0) {
        goto out;
    }
    if (again.len != pw->len || memcmp(again.data, pw->data, pw->len) != 0) {
        fprintf(stderr, "%s: passwords do not match\n", prog);
        goto out;
    }
    ret = 0;
out:
    explicit_bzero(&again, sizeof(again));
    if (ret) {
        explicit_bzero(pw, sizeof(*pw));
    }
    return ret;
}

static int open_ctl(void)
{
    int fd = open(ctl_path, O_RDWR | O_CLOEXEC);

    if (fd < 0) {
        fprintf(stderr, "%s: %s: %s\n", prog, ctl_path, strerror(errno));
    }
    return fd;
}

/* Run a device command; prints the outcome. Returns 0 only for CS_OK. */
static int run(int fd, unsigned long ioc, struct cryptostore_cmd *c, const char *what)
{
    int ret = ioctl(fd, ioc, c);

    explicit_bzero(&c->pw, sizeof(c->pw));
    explicit_bzero(&c->new_pw, sizeof(c->new_pw));
    if (ret < 0) {
        if (errno == EBUSY && ioc == CRYPTOSTORE_IOC_LOCK) {
            fprintf(stderr, "%s: %s: the disk is open or mounted; unmount it first "
                    "(or see 'lock --force')\n", prog, what);
        } else {
            fprintf(stderr, "%s: %s: %s\n", prog, what, strerror(errno));
        }
        return 1;
    }
    if (c->result != CS_OK) {
        fprintf(stderr, "%s: %s: %s", prog, what, result_text(c->result));
        if (c->result == CS_ERR_BACKOFF) {
            fprintf(stderr, " (%u s)", c->aux);
        }
        fputc('\n', stderr);
        return 1;
    }
    return 0;
}

static int cmd_status(void)
{
    struct cryptostore_status st;
    int fd = open_ctl(), rfd;
    uint32_t pw_slots = 0;

    if (fd < 0) {
        return 1;
    }
    memset(&st, 0, sizeof(st));
    if (ioctl(fd, CRYPTOSTORE_IOC_STATUS, &st) < 0) {
        fprintf(stderr, "%s: status: %s\n", prog, strerror(errno));
        close(fd);
        return 1;
    }
    close(fd);
    for (int i = 0; i < 8; i++) {
        pw_slots += (st.slot_map >> i) & 1;
    }
    if (st.slot_map & CS_SLOT_MAP_RECOVERY) {
        pw_slots--;
    }
    printf("device        : %s (%s), block device /dev/%s\n", ctl_path, st.pci_name,
           st.disk_name);
    printf("state         : %s\n", state_name(st.state));
    if (st.state == CS_STATE_UNLOCKED) {
        printf("capacity      : %" PRIu64 " sectors (%" PRIu64 " MiB)\n", (uint64_t)st.capacity,
               (uint64_t)st.capacity * st.sector_size / (1024 * 1024));
    }
    if (st.state != CS_STATE_UNFORMATTED && st.state != CS_STATE_ERROR) {
        printf("failed tries  : %u of %d before lockout\n", st.fail_count, CS_LOCKOUT_N);
        printf("keyslots      : %u password, %s recovery\n", pw_slots,
               st.slot_map & CS_SLOT_MAP_RECOVERY ? "1" : "no");
        printf("uuid          : ");
        for (int i = 0; i < 16; i++) {
            printf("%02x%s", st.uuid[i], (i == 3 || i == 5 || i == 7 || i == 9) ? "-" : "");
        }
        printf("\n");
    }
    printf("recovery dev  : %s\n", st.caps & CS_CAPS_RECOVERY ? "linked and present" : "absent");
    rfd = open(rec_path, O_RDONLY | O_CLOEXEC);
    if (rfd >= 0) {
        struct cryptorecovery_status rs;

        memset(&rs, 0, sizeof(rs));
        if (ioctl(rfd, CRYPTORECOVERY_IOC_STATUS, &rs) == 0) {
            printf("recovery key  : %s%s%s%s\n",
                   rs.status & CR_STATUS_KEY_PRESENT ? "stored" : "none",
                   rs.status & CR_STATUS_ARMED ? ", armed by guest" : "",
                   rs.status & CR_STATUS_HOST_ARMED ? ", host presence confirmed" : "",
                   rs.status & CR_STATUS_RELEASED ? ", already used this boot" : "");
        }
        close(rfd);
    }
    printf("interrupt     : %s\n", st.irq_mode == 3 ? "MSI-X" : st.irq_mode == 2 ? "MSI" : "INTx");
    if (st.caps & CS_CAPS_FAULT_HOOKS) {
        printf("build         : TEST BUILD with fault-injection hooks\n");
    }
    return 0;
}

static int cmd_simple(unsigned long ioc, const char *what, bool ask_pw, bool new_pw, uint32_t flags)
{
    struct cryptostore_cmd c;
    int fd = open_ctl(), ret = 1;

    if (fd < 0) {
        return 1;
    }
    memset(&c, 0, sizeof(c));
    c.flags = flags;
    if (new_pw) {
        if (get_new_password(&c.pw, "New password") < 0) {
            goto out;
        }
    } else if (ask_pw && get_password(&c.pw, "Password: ") < 0) {
        goto out;
    }
    ret = run(fd, ioc, &c, what);
    if (!ret) {
        printf("%s: OK\n", what);
    }
out:
    explicit_bzero(&c, sizeof(c));
    close(fd);
    return ret;
}

static int cmd_passwd(void)
{
    struct cryptostore_status st;
    struct cryptostore_cmd c;
    int fd = open_ctl(), ret = 1;

    if (fd < 0) {
        return 1;
    }
    memset(&c, 0, sizeof(c));
    memset(&st, 0, sizeof(st));
    if (ioctl(fd, CRYPTOSTORE_IOC_STATUS, &st) < 0) {
        goto out;
    }
    /* After RECOVER the old password is unknown; the device asks only for the new one. */
    if (st.state != CS_STATE_RECOVERED && get_password(&c.pw, "Current password: ") < 0) {
        goto out;
    }
    if (get_new_password(&c.new_pw, "New password") < 0) {
        goto out;
    }
    ret = run(fd, CRYPTOSTORE_IOC_PASSWD, &c, "passwd");
    if (!ret) {
        printf("passwd: OK. Old copies of the image still open with the old password "
               "(V7); 'rekey' is the fix and is not in v1.\n");
    }
out:
    explicit_bzero(&c, sizeof(c));
    close(fd);
    return ret;
}

static int cmd_recover(void)
{
    struct cryptorecovery_cmd rc;
    struct cryptostore_cmd c;
    int rfd, fd, ret = 1;

    rfd = open(rec_path, O_RDWR | O_CLOEXEC);
    if (rfd < 0) {
        fprintf(stderr, "%s: %s: %s (is the recovery device attached and cryptorecovery.ko "
                "loaded?)\n", prog, rec_path, strerror(errno));
        return 1;
    }
    memset(&rc, 0, sizeof(rc));
    if (ioctl(rfd, CRYPTORECOVERY_IOC_ARM, &rc) < 0 || rc.result != CR_OK) {
        fprintf(stderr, "%s: recover: could not arm the recovery device (%s)\n", prog,
                rc.result == CR_ERR_NO_KEY ? "it holds no key" : strerror(errno));
        close(rfd);
        return 1;
    }
    close(rfd);
    printf("recover: recovery device armed by the guest\n");

    fd = open_ctl();
    if (fd < 0) {
        return 1;
    }
    memset(&c, 0, sizeof(c));
    if (run(fd, CRYPTOSTORE_IOC_RECOVER, &c, "recover")) {
        if (c.result == CS_ERR_NOT_ARMED) {
            fprintf(stderr, "  The host administrator must confirm presence within 120 s:\n"
                    "    (host) scripts/monitor.sh \"qom-set /machine/peripheral/rec0 "
                    "host-armed true\"\n  then run 'cryptoctl recover' again.\n");
        }
        close(fd);
        return 1;
    }
    printf("recover: key accepted; a new password is required now\n");
    memset(&c, 0, sizeof(c));
    if (get_new_password(&c.new_pw, "New password") == 0) {
        ret = run(fd, CRYPTOSTORE_IOC_PASSWD, &c, "passwd");
        if (!ret) {
            printf("recover: done, device UNLOCKED with the new password\n");
        }
    }
    explicit_bzero(&c, sizeof(c));
    close(fd);
    return ret;
}

static void usage(FILE *f)
{
    fprintf(f,
        "usage: %s [-d CONTROL_NODE] [-r RECOVERY_NODE] COMMAND\n"
        "\n"
        "  status            state, capacity, failure count, keyslots, recovery device\n"
        "  format            set the first password on a blank image\n"
        "  unlock            unlock with the password\n"
        "  lock [--force]    zeroize the key; the disk must not be open or mounted.\n"
        "                    --force locks anyway: WARNING, plaintext may remain in the\n"
        "                    guest page cache (threat model O4) and unwritten data is lost\n"
        "  passwd            change the password (re-wraps the same key; see rekey)\n"
        "  recover           arm the recovery device, recover, set a new password\n"
        "  enroll-recovery   add a recovery key held by the recovery device\n"
        "  rekey             re-encrypt under a new key (not supported in v1)\n"
        "\n"
        "Defaults: -d %s  -r %s\n"
        "Passwords are read from the terminal with echo off, or one per line from\n"
        "stdin when it is not a terminal. They are never taken from the command line.\n",
        prog, ctl_path, rec_path);
}

int main(int argc, char **argv)
{
    const char *cmd;
    int opt;

    harden_process();
    while ((opt = getopt(argc, argv, "+d:r:h")) != -1) {   /* stop at the command */
        switch (opt) {
        case 'd': ctl_path = optarg; break;
        case 'r': rec_path = optarg; break;
        case 'h': usage(stdout); return 0;
        default: usage(stderr); return 2;
        }
    }
    if (optind >= argc) {
        usage(stderr);
        return 2;
    }
    cmd = argv[optind++];

    if (!strcmp(cmd, "status")) {
        return cmd_status();
    } else if (!strcmp(cmd, "format")) {
        return cmd_simple(CRYPTOSTORE_IOC_FORMAT, "format", false, true, 0);
    } else if (!strcmp(cmd, "unlock")) {
        return cmd_simple(CRYPTOSTORE_IOC_UNLOCK, "unlock", true, false, 0);
    } else if (!strcmp(cmd, "lock")) {
        bool force = optind < argc && !strcmp(argv[optind], "--force");
        return cmd_simple(CRYPTOSTORE_IOC_LOCK, "lock", false, false,
                          force ? CRYPTOSTORE_LOCK_FORCE : 0);
    } else if (!strcmp(cmd, "passwd")) {
        return cmd_passwd();
    } else if (!strcmp(cmd, "recover")) {
        return cmd_recover();
    } else if (!strcmp(cmd, "enroll-recovery")) {
        return cmd_simple(CRYPTOSTORE_IOC_ENROLL_RECOVERY, "enroll-recovery", false, false, 0);
    } else if (!strcmp(cmd, "rekey")) {
        return cmd_simple(CRYPTOSTORE_IOC_REKEY, "rekey", false, false, 0);
    }
    usage(stderr);
    return 2;
}
