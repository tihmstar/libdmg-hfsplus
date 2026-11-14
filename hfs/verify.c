/* Read-only structural/allocation checks for bare HFS+/HFSX images.
 * Does not mount, repair, replay journals, or invoke a system checker. */
#define _GNU_SOURCE
#include "verify.h"
#include "../includes/libdmg-hfsplus/hfs/hfsplus.h"

#include <fcntl.h>
#include <inttypes.h>
#include <setjmp.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    uint32_t start, count;
} Ext;
typedef struct {
    uint64_t size;
    uint32_t blocks;
    Ext *ext;
    size_t n;
} Fork;
typedef struct {
    uint32_t id, logical;
    unsigned type;
    Ext ext[8];
} Overflow;
typedef struct {
    uint32_t id, parent, valence, children;
    unsigned folder, state;
} Item;
typedef struct {
    jmp_buf error;
    int fd;
    uint64_t size;
    uint32_t bs, total, free, files, folders, attributes, jinfo;
    unsigned char *used, *bitmap;
    Overflow *overflow;
    size_t noverflow;
    Item *items;
    size_t nitems;
} Check;
typedef struct {
    Check *c;
    Fork fork;
    unsigned kind;
    uint32_t nodes, root, depth, records, first, last, leaf_records, prev, prev_next;
    uint16_t ns;
    unsigned compare;
    unsigned char *map, *seen;
    unsigned char last_leaf_key[518];
    int has_last_leaf_key;
} Tree;
static uint16_t u16(const void *p) {
    const unsigned char *b = p;
    return (uint16_t)((b[0] << 8) | b[1]);
}
static uint32_t u32(const void *p) {
    const unsigned char *b = p;
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}
static uint64_t u64(const void *p) { return ((uint64_t)u32(p) << 32) | u32((const unsigned char *)p + 4); }
static uint64_t little64(const unsigned char *p) {
    return (uint64_t)p[0] | (uint64_t)p[1] << 8 | (uint64_t)p[2] << 16 | (uint64_t)p[3] << 24 |
           (uint64_t)p[4] << 32 | (uint64_t)p[5] << 40 | (uint64_t)p[6] << 48 | (uint64_t)p[7] << 56;
}
static void require(Check *c, int ok, const char *why) {
    if (!ok) {
        fprintf(stderr, "hfsplus verify: %s\n", why);
        longjmp(c->error, 1);
    }
}
static int bit(const unsigned char *b, uint32_t n) { return (b[n / 8] >> (7 - n % 8)) & 1; }
static void set(unsigned char *b, uint32_t n) { b[n / 8] |= (unsigned char)(0x80 >> (n % 8)); }
static void read_at(Check *c, uint64_t off, void *buf, size_t n) {
    unsigned char *p = buf;
    require(c, off <= c->size && n <= c->size - off, "read exceeds image");
    while (n) {
        ssize_t got = pread(c->fd, p, n, (off_t)off);
        require(c, got > 0, "short image read");
        p += got;
        n -= (size_t)got;
        off += (size_t)got;
    }
}
static void mark(Check *c, uint32_t start, uint32_t count) {
    uint32_t i;
    require(c, start < c->total && count <= c->total - start, "extent exceeds volume");
    for (i = 0; i < count; i++) {
        require(c, !bit(c->used, start + i), "block owned by overlapping extents");
        set(c->used, start + i);
    }
}
static void extent_add(Check *c, Fork *f, uint32_t start, uint32_t count) {
    if (!count)
        return;
    require(c, start < c->total && count <= c->total - start, "fork extent bounds");
    f->ext = realloc(f->ext, (f->n + 1) * sizeof(Ext));
    require(c, f->ext != NULL, "extent allocation");
    f->ext[f->n++] = (Ext){start, count};
}
static Fork fork_parse(Check *c, const unsigned char *raw, uint32_t id, unsigned type) {
    Fork f = {0};
    uint64_t blocks = 0;
    unsigned i;
    size_t n;
    f.size = u64(raw);
    f.blocks = u32(raw + 12);
    require(c, f.size <= (uint64_t)f.blocks * c->bs, "fork size exceeds allocation");
    for (i = 0; i < 8; i++) {
        uint32_t count = u32(raw + 20 + 8 * i);
        if (!count) {
            for (; i < 8; i++)
                require(c, !u32(raw + 16 + 8 * i) && !u32(raw + 20 + 8 * i),
                        "nonempty extent after terminator");
            break;
        }
        extent_add(c, &f, u32(raw + 16 + 8 * i), count);
        blocks += count;
    }
    while (blocks < f.blocks) {
        int found = 0;
        uint64_t before = blocks;
        for (n = 0; n < c->noverflow; n++)
            if (c->overflow[n].id == id && c->overflow[n].type == type && c->overflow[n].logical == blocks) {
                for (i = 0; i < 8; i++)
                    if (c->overflow[n].ext[i].count) {
                        extent_add(c, &f, c->overflow[n].ext[i].start, c->overflow[n].ext[i].count);
                        blocks += c->overflow[n].ext[i].count;
                    }
                found = 1;
                break;
            }
        require(c, found && blocks > before, "missing/unsupported extent overflow chain");
    }
    require(c, blocks == f.blocks, "fork extent count mismatch");
    return f;
}
static void fork_mark(Check *c, const Fork *f) {
    size_t i;
    for (i = 0; i < f->n; i++)
        mark(c, f->ext[i].start, f->ext[i].count);
}
static void fork_read(Check *c, const Fork *f, uint64_t off, void *buf, size_t len) {
    uint64_t logical = 0;
    size_t i;
    unsigned char *p = buf;
    require(c, off <= f->size && len <= f->size - off, "fork read bounds");
    for (i = 0; i < f->n && len; i++) {
        uint64_t bytes = (uint64_t)f->ext[i].count * c->bs;
        if (off >= logical + bytes) {
            logical += bytes;
            continue;
        }
        {
            size_t n = logical + bytes - off > len ? len : (size_t)(logical + bytes - off);
            read_at(c, (uint64_t)f->ext[i].start * c->bs + off - logical, p, n);
            p += n;
            len -= n;
            off += n;
            logical += bytes;
        }
    }
    require(c, !len, "short fork mapping");
}
static int cmp32(uint32_t a, uint32_t b) { return a < b ? -1 : a > b; }
static int key_cmp(Tree *t, const unsigned char *a, const unsigned char *b) {
    if (t->kind == 3) {
        int v = cmp32(a[2], b[2]);
        if (v)
            return v;
        v = cmp32(u32(a + 4), u32(b + 4));
        return v ? v : cmp32(u32(a + 8), u32(b + 8));
    }
    if (t->kind == 8) {
        int v = cmp32(u32(a + 4), u32(b + 4));
        unsigned i, n, m;
        if (v)
            return v;
        n = u16(a + 12);
        m = u16(b + 12);
        for (i = 0; i < n && i < m; i++) {
            v = cmp32(u16(a + 14 + 2 * i), u16(b + 14 + 2 * i));
            if (v)
                return v;
        }
        v = cmp32(n, m);
        return v ? v : cmp32(u32(a + 8), u32(b + 8));
    }
    {
        int v = cmp32(u32(a + 2), u32(b + 2));
        uint16_t aa[255], bb[255];
        unsigned n = u16(a + 6), m = u16(b + 6), i;
        if (v)
            return v;
        for (i = 0; i < n; i++)
            aa[i] = u16(a + 8 + 2 * i);
        for (i = 0; i < m; i++)
            bb[i] = u16(b + 8 + 2 * i);
        if (t->compare == kHFSCaseFolding)
            return FastUnicodeCompare(aa, (uint16_t)n, bb, (uint16_t)m);
        for (i = 0; i < n && i < m; i++) {
            v = cmp32(aa[i], bb[i]);
            if (v)
                return v;
        }
        return cmp32(n, m);
    }
}
static unsigned key_size(Tree *t, const unsigned char *p, unsigned available) {
    unsigned n;
    require(t->c, available >= 2, "truncated B-tree key");
    n = u16(p) + 2;
    require(t->c, n <= available && !(n & 1), "B-tree key bounds/alignment");
    if (t->kind == 3)
        require(t->c, n == 12, "extent key size");
    else if (t->kind == 8)
        require(t->c, n >= 14 && u16(p + 12) <= 127 && n == 14 + 2U * u16(p + 12), "attribute key size");
    else
        require(t->c, n >= 8 && u16(p + 6) <= 255 && n == 8 + 2U * u16(p + 6), "catalog key size");
    return n;
}
static void leaf_record(Tree *t, const unsigned char *key, const unsigned char *data, unsigned n) {
    Check *c = t->c;
    if (t->kind == 3) {
        Overflow *o;
        unsigned i;
        require(c, n == 64, "extent overflow record size");
        c->overflow = realloc(c->overflow, (c->noverflow + 1) * sizeof(Overflow));
        require(c, c->overflow != NULL, "overflow memory");
        o = &c->overflow[c->noverflow++];
        o->id = u32(key + 4);
        o->type = key[2];
        o->logical = u32(key + 8);
        for (i = 0; i < 8; i++)
            o->ext[i] = (Ext){u32(data + i * 8), u32(data + i * 8 + 4)};
    } else if (t->kind == 4) {
        unsigned kind;
        require(c, n >= 2, "catalog record header");
        kind = u16(data);
        if (kind == 1 || kind == 2) {
            Item *item;
            require(c, n == (kind == 1 ? 88 : 248), "catalog object record size");
            c->items = realloc(c->items, (c->nitems + 1) * sizeof(Item));
            require(c, c->items != NULL, "catalog memory");
            item = &c->items[c->nitems++];
            *item = (Item){u32(data + 8), u32(key + 2), kind == 1 ? u32(data + 4) : 0, 0, kind == 1, 0};
            if (kind == 2) {
                Fork data_fork = fork_parse(c, data + 88, item->id, 0),
                     resource = fork_parse(c, data + 168, item->id, 0xff);
                fork_mark(c, &data_fork);
                fork_mark(c, &resource);
                free(data_fork.ext);
                free(resource.ext);
            }
        } else
            require(c,
                    (kind == 3 || kind == 4) && n >= 10 && u16(data + 8) <= 255 &&
                        n == 10 + 2U * u16(data + 8),
                    "catalog thread record");
    } else {
        uint32_t kind;
        require(c, n >= 16, "attribute value header");
        kind = u32(data);
        if (kind == 0x10)
            require(c, u32(data + 12) <= n - 16, "inline attribute size");
        else if (kind == 0x20) {
            Fork f;
            require(c, n == 88, "attribute fork size");
            f = fork_parse(c, data + 8, u32(key + 4), 0);
            fork_mark(c, &f);
            free(f.ext);
        } else
            require(c, 0, "unsupported external attribute extent record");
    }
}
static void walk_node(Tree *t, uint32_t number, unsigned height, const unsigned char *minimum) {
    Check *c = t->c;
    unsigned char *node;
    unsigned count, i;
    uint16_t previous = 14;
    const unsigned char *last_key = NULL;
    require(c, number && number < t->nodes && !bit(t->seen, number) && bit(t->map, number),
            "invalid/cyclic B-tree child");
    set(t->seen, number);
    node = malloc(t->ns);
    require(c, node != NULL, "node memory");
    fork_read(c, &t->fork, (uint64_t)number * t->ns, node, t->ns);
    count = u16(node + 10);
    require(c, height && node[9] == height && count && count < (unsigned)(t->ns - 14) / 4,
            "B-tree height/record count");
    require(c, node[8] == (height == 1 ? 0xff : 0), "B-tree node kind");
    if (height == 1) {
        require(c, u32(node + 4) == t->prev && (!t->prev || t->prev_next == number),
                "broken B-tree leaf links");
        if (!t->prev)
            require(c, number == t->first, "wrong first B-tree leaf");
        t->prev = number;
        t->prev_next = u32(node);
    }
    for (i = 0; i < count; i++) {
        uint16_t start = u16(node + t->ns - 2 * (i + 1)), end = u16(node + t->ns - 2 * (i + 2));
        unsigned ksize;
        require(c, start >= 14 && start >= previous && end > start && end <= t->ns - 2 * (count + 1),
                "B-tree record offset table");
        ksize = key_size(t, node + start, end - start);
        if (!i && minimum)
            require(c, !key_cmp(t, minimum, node + start), "B-tree index key differs from child");
        require(c, !last_key || key_cmp(t, last_key, node + start) < 0, "B-tree keys out of order");
        last_key = node + start;
        previous = end;
        if (height == 1) {
            require(c, !t->has_last_leaf_key || key_cmp(t, t->last_leaf_key, node + start) < 0,
                    "B-tree keys out of order across leaves");
            memcpy(t->last_leaf_key, node + start, ksize);
            t->has_last_leaf_key = 1;
            leaf_record(t, node + start, node + start + ksize, end - start - ksize);
            t->leaf_records++;
        } else {
            require(c, end - start - ksize == 4, "index pointer size");
            walk_node(t, u32(node + start + ksize), height - 1, node + start);
        }
    }
    free(node);
}
static void tree_check(Check *c, Fork fork, unsigned kind) {
    Tree t = {0};
    unsigned char head[120], *node;
    uint32_t map_node = 0, nused = 0, free_nodes;
    size_t map_bytes = 0;
    unsigned records;
    uint16_t start, end;
    t.c = c;
    t.fork = fork;
    t.kind = kind;
    if (!fork.size) {
        require(c, !fork.blocks, "empty tree allocation");
        return;
    }
    fork_read(c, &fork, 0, head, sizeof(head));
    t.ns = u16(head + 32);
    t.nodes = u32(head + 36);
    t.root = u32(head + 16);
    t.depth = u16(head + 14);
    t.records = u32(head + 20);
    t.first = u32(head + 24);
    t.last = u32(head + 28);
    t.compare = head[51];
    free_nodes = u32(head + 40);
    require(c,
            t.ns >= 512 && t.ns <= 32768 && !(t.ns & (t.ns - 1)) && t.nodes &&
                (uint64_t)t.nodes * t.ns <= fork.size && free_nodes < t.nodes && t.depth < 32 &&
                head[8] == 1 && u16(head + 10) == 3,
            "invalid B-tree header");
    if (kind == 4)
        require(c, t.compare == kHFSCaseFolding || t.compare == kHFSBinaryCompare, "catalog comparison mode");
    t.map = calloc(1, ((size_t)t.nodes + 7) / 8);
    t.seen = calloc(1, ((size_t)t.nodes + 7) / 8);
    node = malloc(t.ns);
    require(c, t.map && t.seen && node, "B-tree maps allocation");
    do {
        size_t take;
        require(c, map_node < t.nodes && !bit(t.seen, map_node), "B-tree map cycle");
        set(t.seen, map_node);
        fork_read(c, &fork, (uint64_t)map_node * t.ns, node, t.ns);
        records = u16(node + 10);
        require(c, (map_node ? node[8] == 2 && records == 1 : node[8] == 1 && records == 3),
                "B-tree map node kind");
        start = u16(node + t.ns - 2 * records);
        end = u16(node + t.ns - 2 * (records + 1));
        require(c, start >= 14 && end >= start && end <= t.ns - 2 * (records + 1), "B-tree map offsets");
        take = end - start;
        if (take > ((size_t)t.nodes + 7) / 8 - map_bytes)
            take = ((size_t)t.nodes + 7) / 8 - map_bytes;
        memcpy(t.map + map_bytes, node + start, take);
        map_bytes += take;
        map_node = u32(node);
    } while (map_node);
    require(c, map_bytes >= ((size_t)t.nodes + 7) / 8, "B-tree allocation map too short");
    free(node);
    if (t.root)
        walk_node(&t, t.root, t.depth, NULL);
    else
        require(c, !t.records && !t.depth && !t.first && !t.last, "nonempty tree without a root");
    require(c, t.leaf_records == t.records && (!t.root || (t.prev == t.last && !t.prev_next)),
            "B-tree leaf totals or last link");
    for (map_node = 0; map_node < t.nodes; map_node++) {
        require(c, bit(t.map, map_node) == bit(t.seen, map_node), "unreachable or unallocated B-tree node");
        if (bit(t.map, map_node))
            nused++;
    }
    require(c, t.nodes - nused == free_nodes, "B-tree free node count");
    free(t.map);
    free(t.seen);
}
static int item_cmp(const void *a, const void *b) {
    return cmp32(((const Item *)a)->id, ((const Item *)b)->id);
}
static Item *item_find(Check *c, uint32_t id) {
    Item key = {0};
    key.id = id;
    return bsearch(&key, c->items, c->nitems, sizeof(Item), item_cmp);
}
static void catalog_check(Check *c) {
    size_t i;
    uint32_t files = 0, folders = 0;
    qsort(c->items, c->nitems, sizeof(Item), item_cmp);
    for (i = 0; i < c->nitems; i++) {
        Item *n = &c->items[i];
        Item *parent;
        require(c, !i || c->items[i - 1].id != n->id, "duplicate catalog CNID");
        if (n->id == 2)
            require(c, n->folder && n->parent == 1, "invalid root folder");
        else {
            parent = item_find(c, n->parent);
            require(c, parent && parent->folder, "missing/non-directory catalog parent");
            parent->children++;
        }
        if (n->folder) {
            if (n->id != 2)
                folders++;
        } else
            files++;
    }
    for (i = 0; i < c->nitems; i++)
        if (c->items[i].folder)
            require(c, c->items[i].children == c->items[i].valence, "folder valence mismatch");
    require(c, item_find(c, 2) && files == c->files && folders == c->folders,
            "catalog/volume object counts differ");
    item_find(c, 2)->state = 2;
    for (i = 0; i < c->nitems; i++) {
        Item *n = &c->items[i];
        while (!n->state) {
            n->state = 1;
            n = item_find(c, n->parent);
        }
        require(c, n->state == 2, "catalog directory cycle");
        n = &c->items[i];
        while (n->state == 1) {
            n->state = 2;
            n = item_find(c, n->parent);
        }
    }
}
int hfs_verify_image(const char *path) {
    Check *c = calloc(1, sizeof(Check));
    int status = 1;
    struct stat st;
    unsigned char header[512], backup[512];
    if (!c)
        return 1;
    c->fd = -1;
    if (setjmp(c->error) == 0) {
        Fork allocation, extents, catalog, attrs, startup;
        uint32_t i, free_count = 0;
        uint64_t bitmap_size;
        c->fd = open(path, O_RDONLY | O_NOFOLLOW);
        require(c, c->fd >= 0 && !fstat(c->fd, &st) && S_ISREG(st.st_mode) && st.st_size >= 2048,
                "image must be a bare regular filesystem file");
        c->size = (uint64_t)st.st_size;
        read_at(c, 1024, header, sizeof(header));
        require(c,
                (u16(header) == 0x482b && u16(header + 2) == 4) ||
                    (u16(header) == 0x4858 && u16(header + 2) == 5),
                "unsupported HFS volume header");
        c->bs = u32(header + 40);
        c->total = u32(header + 44);
        c->free = u32(header + 48);
        c->files = u32(header + 32);
        c->folders = u32(header + 36);
        c->attributes = u32(header + 4);
        c->jinfo = u32(header + 12);
        require(c,
                c->bs >= 512 && c->bs <= 1048576 && !(c->bs & (c->bs - 1)) && c->total &&
                    (uint64_t)c->total * c->bs <= c->size && c->size - (uint64_t)c->total * c->bs < c->bs &&
                    c->free < c->total,
                "invalid volume geometry");
        require(c, (c->attributes & 0x100) && !(c->attributes & 0x800),
                "unclean/inconsistent volume requires repair");
        read_at(c, c->size - 1024, backup, sizeof(backup));
        require(c, !memcmp(header, backup, 4) && !memcmp(header + 40, backup + 40, 8),
                "alternate volume header geometry differs");
        bitmap_size = ((uint64_t)c->total + 7) / 8;
        c->used = calloc(1, (size_t)bitmap_size);
        c->bitmap = malloc((size_t)bitmap_size);
        require(c, c->used && c->bitmap, "volume bitmap memory");
        mark(c, 0, (1536 + c->bs - 1) / c->bs);
        mark(c, c->total - (1024 + c->bs - 1) / c->bs, (1024 + c->bs - 1) / c->bs);
        extents = fork_parse(c, header + 192, 3, 0);
        fork_mark(c, &extents);
        tree_check(c, extents, 3);
        allocation = fork_parse(c, header + 112, 6, 0);
        catalog = fork_parse(c, header + 272, 4, 0);
        attrs = fork_parse(c, header + 352, 8, 0);
        startup = fork_parse(c, header + 432, 7, 0);
        fork_mark(c, &allocation);
        fork_mark(c, &catalog);
        fork_mark(c, &attrs);
        fork_mark(c, &startup);
        require(c, allocation.size >= bitmap_size, "short allocation bitmap");
        fork_read(c, &allocation, 0, c->bitmap, (size_t)bitmap_size);
        tree_check(c, catalog, 4);
        tree_check(c, attrs, 8);
        catalog_check(c);
        for (i = 0; i < c->total; i++) {
            require(c, bit(c->used, i) == bit(c->bitmap, i), "volume bitmap differs from referenced blocks");
            if (!bit(c->bitmap, i))
                free_count++;
        }
        require(c, free_count == c->free, "free block count differs from bitmap");
        if (c->attributes & 0x2000) {
            unsigned char info[52], journal[48];
            uint64_t off, len, start, end;
            require(c, c->jinfo && c->jinfo < c->total, "invalid journal info block");
            read_at(c, (uint64_t)c->jinfo * c->bs, info, sizeof(info));
            require(c, u32(info) == 1, "journal is external or requires initialization");
            off = u64(info + 36);
            len = u64(info + 44);
            read_at(c, off, journal, sizeof(journal));
            require(c, off && off < c->size && len <= c->size - off, "journal bounds");
            if (u32(journal) == 0x4a4e4c78) {
                start = u64(journal + 8);
                end = u64(journal + 16);
                require(c, u64(journal + 24) == len, "journal length");
            } else {
                require(c, !memcmp(journal, "xLNJxV4\x12", 8), "journal magic");
                start = little64(journal + 8);
                end = little64(journal + 16);
                require(c, little64(journal + 24) == len, "journal length");
            }
            require(c, start == end && start >= 512 && start < len, "journal has pending transactions");
        } else
            require(c, !c->jinfo, "unjournaled image has a journal pointer");
        free(extents.ext);
        free(allocation.ext);
        free(catalog.ext);
        free(attrs.ext);
        free(startup.ext);
        printf("The HFS%s volume appears to be OK. Checked catalog, B-trees, forks, allocation bitmap and "
               "journal.\n",
               u16(header) == 0x4858 ? "X" : "+");
        status = 0;
    }
    if (c->fd >= 0)
        close(c->fd);
    free(c->used);
    free(c->bitmap);
    free(c->overflow);
    free(c->items);
    free(c);
    return status;
}
