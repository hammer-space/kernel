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

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/richacl_compat.h>

/**
 * richacl_prepare  -  allocate richacl being constructed
 *
 * Allocate a richacl which can hold @count entries but which is initially
 * empty.
 */
struct richacl *richacl_prepare(struct richacl_alloc *alloc, unsigned int count)
{
	alloc->acl = richacl_alloc(count, GFP_KERNEL);
	if (!alloc->acl)
		return NULL;
	alloc->acl->a_count = 0;
	alloc->count = count;
	return alloc->acl;
}
EXPORT_SYMBOL_GPL(richacl_prepare);

/**
 * richacl_delete_entry  -  delete an entry in an acl
 * @alloc:	acl and number of allocated entries
 * @ace:	an entry in @alloc->acl
 *
 * Updates @ace so that it points to the entry before the deleted entry
 * on return. (When deleting the first entry, @ace will point to the
 * (non-existent) entry before the first entry). This behavior is the
 * expected behavior when deleting entries while forward iterating over
 * an acl.
 */
void
richacl_delete_entry(struct richacl_alloc *alloc, struct richace **ace)
{
	void *end = alloc->acl->a_entries + alloc->acl->a_count;

	memmove(*ace, *ace + 1, end - (void *)(*ace + 1));
	(*ace)--;
	alloc->acl->a_count--;
}
EXPORT_SYMBOL_GPL(richacl_delete_entry);

/**
 * richacl_insert_entry  -  insert an entry in an acl
 * @alloc:	acl and number of allocated entries
 * @ace:	entry before which the new entry shall be inserted
 *
 * Insert a new entry in @alloc->acl at position @ace and zero-initialize
 * it.  This may require reallocating @alloc->acl.
 */
int
richacl_insert_entry(struct richacl_alloc *alloc, struct richace **ace)
{
	struct richacl *acl = alloc->acl;
	unsigned int index = *ace - acl->a_entries;
	size_t tail_size = (acl->a_count - index) * sizeof(struct richace);

	if (alloc->count == acl->a_count) {
		size_t new_size = sizeof(struct richacl) +
			(acl->a_count + 1) * sizeof(struct richace);

		acl = krealloc(acl, new_size, GFP_KERNEL);
		if (!acl)
			return -1;
		*ace = acl->a_entries + index;
		alloc->acl = acl;
		alloc->count++;
	}

	memmove(*ace + 1, *ace, tail_size);
	memset(*ace, 0, sizeof(**ace));
	acl->a_count++;
	return 0;
}
EXPORT_SYMBOL_GPL(richacl_insert_entry);

/**
 * richacl_append_entry  -  append an entry to an acl
 * @alloc:		acl and number of allocated entries
 *
 * This may require reallocating @alloc->acl.
 */
struct richace *richacl_append_entry(struct richacl_alloc *alloc)
{
	struct richacl *acl = alloc->acl;
	struct richace *ace = acl->a_entries + acl->a_count;

	if (alloc->count > alloc->acl->a_count) {
		acl->a_count++;
		return ace;
	}
	return richacl_insert_entry(alloc, &ace) ? NULL : ace;
}
EXPORT_SYMBOL_GPL(richacl_append_entry);

/**
 * richace_change_mask  -  set the mask of @ace to @mask
 * @alloc:	acl and number of allocated entries
 * @ace:	entry to modify
 * @mask:	new mask for @ace
 *
 * If @ace is inheritable, a inherit-only ace is inserted before @ace which
 * includes the inheritable permissions of @ace and the inheritance flags of
 * @ace are cleared before changing the mask.
 *
 * If @mask is 0, the original ace is turned into an inherit-only entry if
 * there are any inheritable permissions, and removed otherwise.
 *
 * The returned @ace points to the modified or inserted effective-only acl
 * entry if that entry exists, to the entry that has become inheritable-only,
 * or else to the previous entry in the acl.
 */
static int
richace_change_mask(struct richacl_alloc *alloc, struct richace **ace,
			   unsigned int mask)
{
	if (mask && (*ace)->e_mask == mask)
		(*ace)->e_flags &= ~RICHACE_INHERIT_ONLY_ACE;
	else if (mask & ~RICHACE_POSIX_ALWAYS_ALLOWED) {
		if (richace_is_inheritable(*ace)) {
			if (richacl_insert_entry(alloc, ace))
				return -1;
			richace_copy(*ace, *ace + 1);
			(*ace)->e_flags |= RICHACE_INHERIT_ONLY_ACE;
			(*ace)++;
			(*ace)->e_flags &= ~RICHACE_INHERITANCE_FLAGS |
					   RICHACE_INHERITED_ACE;
		}
		(*ace)->e_mask = mask;
	} else {
		if (richace_is_inheritable(*ace))
			(*ace)->e_flags |= RICHACE_INHERIT_ONLY_ACE;
		else
			richacl_delete_entry(alloc, ace);
	}
	return 0;
}

/**
 * richacl_move_everyone_aces_down  -  move everyone@ aces to the end of the acl
 * @alloc:	acl and number of allocated entries
 *
 * Move all everyone aces to the end of the acl so that only a single everyone@
 * allow ace remains at the end, and update the mask fields of all aces on the
 * way.  The last ace of the resulting acl will be an everyone@ allow ace only
 * if @acl grants any permissions to @everyone.  No @everyone deny aces will
 * remain.
 *
 * This transformation does not alter the permissions that the acl grants.
 * Having at most one everyone@ allow ace at the end of the acl helps us in the
 * following algorithms.
 */
static int
richacl_move_everyone_aces_down(struct richacl_alloc *alloc)
{
	struct richace *ace;
	unsigned int allowed = 0, denied = 0;

	richacl_for_each_entry(ace, alloc->acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_everyone(ace)) {
			if (richace_is_allow(ace))
				allowed |= (ace->e_mask & ~denied);
			else if (richace_is_deny(ace))
				denied |= (ace->e_mask & ~allowed);
			else
				continue;
			if (richace_change_mask(alloc, &ace, 0))
				return -1;
		} else {
			if (richace_is_allow(ace)) {
				if (richace_change_mask(alloc, &ace, allowed |
						(ace->e_mask & ~denied)))
					return -1;
			} else if (richace_is_deny(ace)) {
				if (richace_change_mask(alloc, &ace, denied |
						(ace->e_mask & ~allowed)))
					return -1;
			}
		}
	}
	if (allowed & ~RICHACE_POSIX_ALWAYS_ALLOWED) {
		struct richace *last_ace = ace - 1;

		if (alloc->acl->a_entries &&
		    richace_is_everyone(last_ace) &&
		    richace_is_allow(last_ace) &&
		    richace_is_inherit_only(last_ace) &&
		    last_ace->e_mask == allowed)
			last_ace->e_flags &= ~RICHACE_INHERIT_ONLY_ACE;
		else {
			if (richacl_insert_entry(alloc, &ace))
				return -1;
			ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
			ace->e_flags = RICHACE_SPECIAL_WHO;
			ace->e_mask = allowed;
			ace->e_id.special = RICHACE_EVERYONE_SPECIAL_ID;
		}
	}
	return 0;
}
