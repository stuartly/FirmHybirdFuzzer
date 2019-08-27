/* AUTOMATICALLY GENERATED, DO NOT MODIFY */
/*
 * QEMU Block Module Infrastructure
 *
 * Authors:
 *  Marc Mari       <markmb@redhat.com>
 */

#ifndef QEMU_MODULE_BLOCK_H
#define QEMU_MODULE_BLOCK_H

#include "qemu-common.h"

static const struct {
    const char *format_name;
    const char *protocol_name;
    const char *library_name;
} block_driver_modules[] = {
    {
        .library_name = "iscsi",
        .format_name = "iscsi",
        .protocol_name = "iscsi",
    },
    {
        .library_name = "iscsi",
        .format_name = "iser",
        .protocol_name = "iser",
    },
    {
        .library_name = "nfs",
        .format_name = "nfs",
        .protocol_name = "nfs",
    },
    {
        .library_name = "curl",
        .format_name = "http",
        .protocol_name = "http",
    },
    {
        .library_name = "curl",
        .format_name = "https",
        .protocol_name = "https",
    },
    {
        .library_name = "curl",
        .format_name = "ftp",
        .protocol_name = "ftp",
    },
    {
        .library_name = "curl",
        .format_name = "ftps",
        .protocol_name = "ftps",
    },
    {
        .library_name = "rbd",
        .format_name = "rbd",
        .protocol_name = "rbd",
    },
    {
        .library_name = "ssh",
        .format_name = "ssh",
        .protocol_name = "ssh",
    },
};

#endif
