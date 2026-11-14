/* Native formatter for fresh bare HFS+/HFSX images. No donor, mount, or
 * external mkfs process. Allocation and B-tree maps are created from scratch. */
#define _GNU_SOURCE
#include "../includes/libdmg-hfsplus/hfs/hfsplus.h"
#include "format.h"

#include <inttypes.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static void be16(void *p, uint16_t v) {
    unsigned char *b = p;
    b[0] = v >> 8;
    b[1] = v;
}
static void be32(void *p, uint32_t v) {
    unsigned char *b = p;
    b[0] = v >> 24;
    b[1] = v >> 16;
    b[2] = v >> 8;
    b[3] = v;
}
static void be64(void *p, uint64_t v) {
    be32(p, (uint32_t)(v >> 32));
    be32((unsigned char *)p + 4, (uint32_t)v);
}
static int write_at(int fd, uint64_t at, const void *data, size_t n) {
    const unsigned char *p = data;
    while (n) {
        ssize_t done = pwrite(fd, p, n, (off_t)at);
        if (done < 0 && errno == EINTR)
            continue;
        if (done <= 0)
            return 0;
        p += done;
        at += (size_t)done;
        n -= (size_t)done;
    }
    return 1;
}
static int parse_size(const char *s, uint64_t *out) {
    char *end;
    uint64_t value, mult = 1;
    if (!*s || *s == '-' || *s == '+')
        return 0;
    errno = 0;
    value = strtoull(s, &end, 10);
    if (errno || end == s)
        return 0;
    if (*end) {
        switch (*end++) {
        case 'k':
        case 'K':
            mult = 1024;
            break;
        case 'm':
        case 'M':
            mult = 1024 * 1024;
            break;
        case 'g':
        case 'G':
            mult = UINT64_C(1024) * 1024 * 1024;
            break;
        case 't':
        case 'T':
            mult = UINT64_C(1024) * 1024 * 1024 * 1024;
            break;
        default:
            return 0;
        }
        if (*end == 'i')
            end++;
        if (*end == 'b' || *end == 'B')
            end++;
        if (*end)
            return 0;
    }
    if (value > INT64_MAX / mult)
        return 0;
    *out = value * mult;
    return 1;
}
static void fork_header(unsigned char *p, uint64_t logical, uint32_t block, uint32_t count, uint32_t bs) {
    be64(p, logical);
    be32(p + 8, count * bs);
    be32(p + 12, count);
    be32(p + 16, block);
    be32(p + 20, count);
}
static int tree_header(int fd, uint64_t at, uint32_t bytes, uint16_t node_size, uint16_t max_key,
                       unsigned compare, int catalog) {
    unsigned char *node = calloc(1, node_size);
    uint32_t count = bytes / node_size;
    int ok;
    if (!node)
        return 0;
    node[8] = kBTHeaderNode;
    be16(node + 10, 3);
    be16(node + 14, catalog ? 1 : 0);
    be32(node + 16, catalog ? 1 : 0);
    be32(node + 20, catalog ? 2 : 0);
    be32(node + 24, catalog ? 1 : 0);
    be32(node + 28, catalog ? 1 : 0);
    be16(node + 32, node_size);
    be16(node + 34, max_key);
    be32(node + 36, count);
    be32(node + 40, count - (catalog ? 2 : 1));
    be32(node + 46, bytes);
    node[51] = (unsigned char)compare;
    be32(node + 52, max_key == 10 ? 2 : 6);
    /* Header record, 128-byte user record, allocation map, free space. */
    node[248] = catalog ? 0xc0 : 0x80;
    be16(node + node_size - 2, 14);
    be16(node + node_size - 4, 120);
    be16(node + node_size - 6, 248);
    be16(node + node_size - 8, node_size - 8);
    ok = write_at(fd, at, node, node_size);
    free(node);
    return ok;
}
static int root_catalog(int fd, uint64_t at, uint16_t node_size, const char *name, uint32_t date) {
    unsigned char *node = calloc(1, node_size);
    HFSPlusCatalogFolder root = {0};
    size_t n = strlen(name), i;
    uint16_t first = 14, second, end;
    int ok;
    if (!node)
        return 0;
    node[8] = 0xff;
    node[9] = 1;
    be16(node + 10, 2);
    be16(node + first, (uint16_t)(6 + n * 2));
    be32(node + first + 2, 1);
    be16(node + first + 6, (uint16_t)n);
    for (i = 0; i < n; i++)
        be16(node + first + 8 + i * 2, (unsigned char)name[i]);
    root.recordType = kHFSPlusFolderRecord;
    root.folderID = kHFSRootFolderID;
    root.createDate = root.contentModDate = root.attributeModDate = root.accessDate = date;
    root.permissions.fileMode = S_IFDIR | 0755;
    flipCatalogFolder(&root);
    memcpy(node + first + 8 + n * 2, &root, sizeof(root));
    second = (uint16_t)(first + 8 + n * 2 + sizeof(root));
    be16(node + second, 6);
    be32(node + second + 2, 2);
    be16(node + second + 6, 0);
    be16(node + second + 8, kHFSPlusFolderThreadRecord);
    be32(node + second + 12, 1);
    be16(node + second + 16, (uint16_t)n);
    for (i = 0; i < n; i++)
        be16(node + second + 18 + i * 2, (unsigned char)name[i]);
    end = (uint16_t)(second + 18 + n * 2);
    be16(node + node_size - 2, first);
    be16(node + node_size - 4, second);
    be16(node + node_size - 6, end);
    ok = write_at(fd, at, node, node_size);
    free(node);
    return ok;
}
static int create(const char *output, uint64_t size, uint32_t bs, const char *name, int sensitive) {
    uint64_t total = size / bs, bitmap_bytes = (total + 7) / 8;
    uint32_t front = (1536 + bs - 1) / bs, back = (1024 + bs - 1) / bs;
    uint32_t bitmap_blocks = (uint32_t)((bitmap_bytes + bs - 1) / bs);
    /* Full firmware roots need large contiguous system B-trees. Restore
     * ramdisks have only hundreds of records and cannot afford those minima. */
    uint32_t ext_bytes = size < UINT64_C(512) * 1024 * 1024 ? 256U * 1024 : 4U * 1024 * 1024;
    uint32_t cat_bytes = size < UINT64_C(512) * 1024 * 1024 ? 2U * 1024 * 1024 : 24U * 1024 * 1024;
    uint32_t attr_bytes = size < UINT64_C(512) * 1024 * 1024 ? 1U * 1024 * 1024 : 16U * 1024 * 1024;
    uint32_t ext_blocks = (ext_bytes + bs - 1) / bs;
    uint32_t cat_blocks = (cat_bytes + bs - 1) / bs;
    uint32_t attr_blocks = (attr_bytes + bs - 1) / bs;
    uint32_t bitmap_start = front, ext_start = bitmap_start + bitmap_blocks,
             cat_start = ext_start + ext_blocks;
    uint32_t attr_start = cat_start + cat_blocks, used = attr_start + attr_blocks;
    uint32_t date = (uint32_t)((uint64_t)time(NULL) + UINT64_C(2082844800));
    unsigned char header[512] = {0};
    unsigned char *bitmap = NULL;
    char *temporary = NULL;
    int fd = -1, ok = 0;
    uint64_t i;
    if (total > UINT32_MAX || total <= used + back || bitmap_bytes > SIZE_MAX)
        return 0;
    bitmap = calloc(1, (size_t)bitmap_blocks * bs);
    temporary = malloc(strlen(output) + 16);
    if (!bitmap || !temporary)
        goto done;
    sprintf(temporary, "%s.partial-XXXXXX", output);
    fd = mkstemp(temporary);
    if (fd < 0)
        goto done;
    if (ftruncate(fd, (off_t)size))
        goto done;
    for (i = 0; i < used; i++)
        bitmap[i / 8] |= (unsigned char)(0x80 >> (i % 8));
    for (i = total - back; i < bitmap_bytes * 8; i++)
        bitmap[i / 8] |= (unsigned char)(0x80 >> (i % 8));
    be16(header, sensitive ? 0x4858 : 0x482b);
    be16(header + 2, sensitive ? 5 : 4);
    be32(header + 4, 0x100);
    be32(header + 8, 0x31302e30);
    be32(header + 16, date);
    be32(header + 20, date);
    be32(header + 40, bs);
    be32(header + 44, (uint32_t)total);
    be32(header + 48, (uint32_t)total - used - back);
    be32(header + 52, used);
    be32(header + 56, bs * 16);
    be32(header + 60, bs * 16);
    be32(header + 64, 16);
    be32(header + 68, 1);
    be64(header + 72, 1);
    {
        int random = open("/dev/urandom", O_RDONLY);
        if (random >= 0) {
            ssize_t n = read(random, header + 104, 8);
            close(random);
            if (n != 8)
                memset(header + 104, 0, 8);
        }
    }
    fork_header(header + 112, bitmap_bytes, bitmap_start, bitmap_blocks, bs);
    fork_header(header + 192, (uint64_t)ext_blocks * bs, ext_start, ext_blocks, bs);
    fork_header(header + 272, (uint64_t)cat_blocks * bs, cat_start, cat_blocks, bs);
    fork_header(header + 352, (uint64_t)attr_blocks * bs, attr_start, attr_blocks, bs);
    if (!write_at(fd, (uint64_t)bitmap_start * bs, bitmap, (size_t)bitmap_blocks * bs) ||
        !tree_header(fd, (uint64_t)ext_start * bs, ext_blocks * bs, 4096, 10, 0, 0) ||
        !tree_header(fd, (uint64_t)cat_start * bs, cat_blocks * bs, 8192, 516,
                     sensitive ? kHFSBinaryCompare : kHFSCaseFolding, 1) ||
        !root_catalog(fd, (uint64_t)cat_start * bs + 8192, 8192, name, date) ||
        !tree_header(fd, (uint64_t)attr_start * bs, attr_blocks * bs, 8192, 266, 0, 0) ||
        !write_at(fd, 1024, header, sizeof(header)) || !write_at(fd, size - 1024, header, sizeof(header)) ||
        fsync(fd))
        goto done;
    /* link refuses existing files, symlinks and hardlink aliases atomically. */
    if (link(temporary, output))
        goto done;
    ok = 1;
done:
    if (fd >= 0)
        close(fd);
    if (temporary) {
        unlink(temporary);
        free(temporary);
    }
    free(bitmap);
    if (!ok)
        fprintf(stderr, "hfsplus create: cannot format/publish image: %s\n", strerror(errno));
    return ok;
}
int hfs_format_command(int argc, const char *argv[]) {
    uint64_t size, value;
    uint32_t bs = 4096;
    const char *name = "Untitled";
    int sensitive = 0, i;
    struct stat st;
    if (argc < 4 || !parse_size(argv[3], &size))
        goto usage;
    for (i = 4; i < argc; i++) {
        if (!strcmp(argv[i], "-s"))
            sensitive = 1;
        else if (!strcmp(argv[i], "-i"))
            sensitive = 0;
        else if (!strcmp(argv[i], "-n") && i + 1 < argc)
            name = argv[++i];
        else if (!strcmp(argv[i], "-b") && i + 1 < argc) {
            if (!parse_size(argv[++i], &value) || value > UINT32_MAX)
                goto usage;
            bs = (uint32_t)value;
        } else
            goto usage;
    }
    if (!*name || strlen(name) > 255)
        goto usage;
    /* Firmware volume names are ASCII; refuse unsupported normalization. */
    for (i = 0; name[i]; i++)
        if ((unsigned char)name[i] < 32 || (unsigned char)name[i] > 126 || name[i] == '/' || name[i] == ':')
            goto usage;
    if (bs < 512 || bs > 1048576 || (bs & (bs - 1)) || size < 16 * 1024 * 1024 || size % bs ||
        size / bs > UINT32_MAX)
        goto usage;
    if (!lstat(argv[1], &st)) {
        fprintf(stderr, "hfsplus create: output already exists\n");
        return 1;
    }
    if (errno != ENOENT) {
        perror("hfsplus create");
        return 1;
    }
    if (!create(argv[1], size, bs, name, sensitive))
        return 1;
    printf("created %s: %" PRIu64 " bytes, %s, block size %u\n", argv[1], size, sensitive ? "HFSX" : "HFS+",
           bs);
    return 0;
usage:
    fprintf(stderr,
            "usage: hfsplus <new.raw> create <size> [-n ASCII-name] [-s|-i] [-b blocksize]\n"
            "  sizes accept k/m/g/t; minimum 16 MiB, aligned to a 512..1048576-byte power-of-two block size\n"
            "  default: HFS+ case-insensitive, 4096-byte blocks; -s creates case-sensitive HFSX\n"
            "  creates a bare sparse, unjournaled filesystem; output must not exist\n");
    return 1;
}
