/*
 * Copyright (C) 2006, 2010  Novell, Inc.
 * Copyright (C) 2015  Red Hat, Inc.
 * Written by Andreas Gruenbacher <agruenba@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#ifndef __RICHACL_XATTR_H
#define __RICHACL_XATTR_H

#include <uapi/linux/richacl_xattr.h>
#include <linux/richacl.h>

extern struct richacl *richacl_from_xattr(struct user_namespace *, const void *,
					  size_t, int);
extern size_t richacl_xattr_size(const struct richacl *);
extern int richacl_to_xattr(struct user_namespace *, const struct richacl *,
			    void *, size_t);

extern struct xattr_handler richacl_xattr_handler;

#endif /* __RICHACL_XATTR_H */
