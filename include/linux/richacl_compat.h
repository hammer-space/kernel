/*
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

#ifndef __RICHACL_COMPAT_H
#define __RICHACL_COMPAT_H

#include <linux/richacl.h>

/**
 * struct richacl_alloc  -  remember how many entries are actually allocated
 * @acl:	acl with a_count <= @count
 * @count:	the actual number of entries allocated in @acl
 *
 * We pass around this structure while modifying an acl so that we do
 * not have to reallocate when we remove existing entries followed by
 * adding new entries.
 */
struct richacl_alloc {
	struct richacl *acl;
	unsigned int count;
};

struct richacl *richacl_prepare(struct richacl_alloc *, unsigned int);
struct richace *richacl_append_entry(struct richacl_alloc *);
int richacl_insert_entry(struct richacl_alloc *, struct richace **);
void richacl_delete_entry(struct richacl_alloc *, struct richace **);

#endif  /* __RICHACL_COMPAT_H */
