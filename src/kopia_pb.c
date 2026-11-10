/* kopia_pb.c — minimal protobuf wire helpers (varint + length-delimited). */

#include <string.h>

#include "kopia_internal.h"

void pb_write_varint(unsigned char *buf, size_t *len, uint64_t v) {
    while (v >= 0x80) {
        buf[(*len)++] = (unsigned char)(v | 0x80);
        v >>= 7;
    }
    buf[(*len)++] = (unsigned char)v;
}

void pb_write_tag(unsigned char *buf, size_t *len, int field, int wire) {
    pb_write_varint(buf, len, ((uint64_t)field << 3) | (uint64_t)wire);
}

void pb_write_string(unsigned char *buf, size_t *len, int field, const void *data, size_t n) {
    pb_write_tag(buf, len, field, 2);
    pb_write_varint(buf, len, n);
    memcpy(buf + *len, data, n);
    *len += n;
}

void pb_write_msg(unsigned char *buf, size_t *len, int field, const unsigned char *msg, size_t n) {
    pb_write_string(buf, len, field, msg, n);
}

static uint64_t read_varint(const unsigned char *buf, size_t len, size_t *pos) {
    uint64_t v = 0;
    int shift = 0;
    while (*pos < len) {
        unsigned char b = buf[(*pos)++];
        v |= (uint64_t)(b & 0x7f) << shift;
        if (!(b & 0x80)) break;
        shift += 7;
    }
    return v;
}

int pb_parse(const unsigned char *buf, size_t len, pb_field_t *out, int max) {
    size_t pos = 0;
    int n = 0;
    while (pos < len && n < max) {
        uint64_t tag = read_varint(buf, len, &pos);
        int field = (int)(tag >> 3);
        int wire = (int)(tag & 7);
        if (field == 0) break;
        out[n].field = field;
        out[n].wire = wire;
        out[n].vint = 0;
        out[n].ptr = NULL;
        out[n].len = 0;
        if (wire == 0) {
            out[n].vint = read_varint(buf, len, &pos);
        } else if (wire == 2) {
            uint64_t l = read_varint(buf, len, &pos);
            if (pos + l > len) break;
            out[n].ptr = buf + pos;
            out[n].len = (size_t)l;
            pos += l;
        } else {
            break; /* unsupported wire type */
        }
        n++;
    }
    return n;
}
