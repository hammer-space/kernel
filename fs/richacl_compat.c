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

/**
 * __richacl_propagate_everyone  -  propagate everyone@ permissions up for @who
 * @alloc:	acl and number of allocated entries
 * @who:	identifier to propagate permissions for
 * @allow:	permissions to propagate up
 *
 * Propagate the permissions in @allow up from the end of the acl to the start
 * for the specified principal @who.
 *
 * The simplest possible approach to achieve this would be to insert a
 * "<who>:<allow>::allow" ace before the final everyone@ allow ace.  Since this
 * would often result in aces which are not needed or which could be merged
 * with an existing ace, we make the following optimizations:
 *
 *   - We go through the acl and determine which permissions are already
 *     allowed or denied to @who, and we remove those permissions from
 *     @allow.
 *
 *   - If the acl contains an allow ace for @who and no aces after this entry
 *     deny permissions in @allow, we add the permissions in @allow to this
 *     ace.  (Propagating permissions across a deny ace which can match the
 *     process can elevate permissions.)
 *
 * This transformation does not alter the permissions that the acl grants.
 */
static int
__richacl_propagate_everyone(struct richacl_alloc *alloc, struct richace *who,
			     unsigned int allow)
{
	struct richace *allow_last = NULL, *ace;
	struct richacl *acl = alloc->acl;

	/*
	 * Remove the permissions from allow that are already determined for
	 * this who value, and figure out if there is an allow entry for
	 * this who value that is "reachable" from the trailing everyone@
	 * allow ace.
	 */
	richacl_for_each_entry(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_allow(ace)) {
			if (richace_is_same_identifier(ace, who)) {
				allow &= ~ace->e_mask;
				allow_last = ace;
			}
		} else if (richace_is_deny(ace)) {
			if (richace_is_same_identifier(ace, who))
				allow &= ~ace->e_mask;
			else if (allow & ace->e_mask)
				allow_last = NULL;
		}
	}
	ace--;

	/*
	 * If for group class entries, all the remaining permissions will
	 * remain granted by the trailing everyone@ allow ace, no additional
	 * entry is needed.
	 */
	if (!richace_is_owner(who) &&
	    richace_is_everyone(ace) &&
	    !(allow & ~(ace->e_mask & acl->a_other_mask)))
		allow = 0;

	if (allow) {
		if (allow_last)
			return richace_change_mask(alloc, &allow_last,
						   allow_last->e_mask | allow);
		else {
			struct richace who_copy;

			richace_copy(&who_copy, who);
			if (richacl_insert_entry(alloc, &ace))
				return -1;
			richace_copy(ace, &who_copy);
			ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
			ace->e_flags &= ~RICHACE_INHERITANCE_FLAGS;
			ace->e_mask = allow;
		}
	}
	return 0;
}

/**
 * richacl_propagate_everyone  -  propagate everyone@ permissions up the acl
 * @alloc:	acl and number of allocated entries
 *
 * Make sure that group@ and all other users and groups mentioned in the acl
 * will not lose any permissions when finally applying the other mask to the
 * everyone@ allow ace at the end of the acl.  We modify the permissions of
 * existing entries or add new entries before the final everyone@ allow ace to
 * achieve that.
 *
 * For example, the following acl implicitly grants everyone rwpx access:
 *
 *    joe:r::allow
 *    everyone@:rwpx::allow
 *
 * When applying mode 0660 to this acl, group@ would lose rwp access, and joe
 * would lose wp access even though the mode does not exclude those
 * permissions.  After propagating the everyone@ permissions, the result for
 * applying mode 0660 becomes:
 *
 *    owner@:rwp::allow
 *    joe:rwp::allow
 *    group@:rwp::allow
 *
 * Deny aces complicate the matter.  For example, the following acl grants
 * everyone but joe write access:
 *
 *    joe:wp::deny
 *    everyone@:rwpx::allow
 *
 * When applying mode 0660 to this acl, group@ would lose rwp access, and joe
 * would lose r access.  After propagating the everyone@ permissions, the
 * result for applying mode 0660 becomes:
 *
 *    owner@:rwp::allow
 *    joe:w::deny
 *    group@:rwp::allow
 *    joe:r::allow
 */
static int
richacl_propagate_everyone(struct richacl_alloc *alloc)
{
	struct richace who = { .e_flags = RICHACE_SPECIAL_WHO };
	struct richacl *acl = alloc->acl;
	struct richace *ace;
	unsigned int owner_allow, group_allow;

	if (!acl->a_count)
		return 0;
	ace = acl->a_entries + acl->a_count - 1;
	if (richace_is_inherit_only(ace) || !richace_is_everyone(ace))
		return 0;

	/*
	 * Permissions the owner and group class are granted through the
	 * trailing everyone@ allow ace.
	 */
	owner_allow = ace->e_mask & acl->a_owner_mask;
	group_allow = ace->e_mask & acl->a_group_mask;

	/*
	 * If the group or other masks hide permissions which the owner should
	 * be allowed, we need to propagate those permissions up.  Otherwise,
	 * those permissions may be lost when applying the other mask to the
	 * trailing everyone@ allow ace, or when isolating the group class from
	 * the other class through additional deny aces.
	 */
	if (owner_allow & ~(acl->a_group_mask & acl->a_other_mask)) {
		/* Propagate everyone@ permissions through to owner@. */
		who.e_id.special = RICHACE_OWNER_SPECIAL_ID;
		if (__richacl_propagate_everyone(alloc, &who, owner_allow))
			return -1;
		acl = alloc->acl;
	}

	/*
	 * If the other mask hides permissions which the group class should be
	 * allowed, we need to propagate those permissions up to the owning
	 * group and to all other members in the group class.
	 */
	if (group_allow & ~acl->a_other_mask) {
		int n;

		/* Propagate everyone@ permissions through to group@. */
		who.e_id.special = RICHACE_GROUP_SPECIAL_ID;
		if (__richacl_propagate_everyone(alloc, &who, group_allow))
			return -1;
		acl = alloc->acl;

		/*
		 * Start from the entry before the trailing everyone@ allow
		 * entry. We will not hit everyone@ entries in the loop.
		 */
		for (n = acl->a_count - 2; n != -1; n--) {
			ace = acl->a_entries + n;

			if (richace_is_inherit_only(ace) ||
			    richace_is_owner(ace) ||
			    richace_is_group(ace))
				continue;

			/*
			 * Any inserted entry will end up below the current
			 * entry.
			 */
			if (__richacl_propagate_everyone(alloc, ace,
							 group_allow))
				return -1;
			acl = alloc->acl;
		}
	}
	return 0;
}

/**
 * richacl_set_owner_permissions  -  set the owner permissions to the owner mask
 *
 * In the write-through case, change the acl so that owner@ is granted the
 * permissions set in the owner mask (to match what the permission check
 * algorithm grants the owner).  This leaves at most one efective owner@ allow
 * entry at the beginning of the acl.
 */
static int
richacl_set_owner_permissions(struct richacl_alloc *alloc)
{
	unsigned int x = RICHACE_POSIX_ALWAYS_ALLOWED;
	unsigned int owner_mask = alloc->acl->a_owner_mask & ~x;
	unsigned int denied = 0;
	struct richace *ace;

	if (!((alloc->acl->a_flags & RICHACL_WRITE_THROUGH)))
		return 0;

	richacl_for_each_entry(ace, alloc->acl) {
		if (richace_is_owner(ace)) {
			if (richace_is_allow(ace) && !(owner_mask & denied)) {
				richace_change_mask(alloc, &ace, owner_mask);
				owner_mask = 0;
			} else
				richace_change_mask(alloc, &ace, 0);
		} else {
			if (richace_is_deny(ace))
				denied |= ace->e_mask;
		}
	}

	if (owner_mask & (denied |
			  ~alloc->acl->a_other_mask |
			  ~alloc->acl->a_group_mask)) {
		ace = alloc->acl->a_entries;
		if (richacl_insert_entry(alloc, &ace))
			return -1;
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = owner_mask;
		ace->e_id.special = RICHACE_OWNER_SPECIAL_ID;
	}
	return 0;
}

/**
 * richacl_set_other_permissions  -  set the other permissions to the other mask
 * @alloc:	acl and number of allocated entries
 * @added:	permissions added for everyone@
 *
 * Change the acl so that everyone@ is granted the permissions set in the other
 * mask.  This leaves at most one efective everyone@ allow entry at the end of
 * the acl.  If everyone@ end up being granted additional permissions, these
 * permissions are returned in @added.
 */
static int
richacl_set_other_permissions(struct richacl_alloc *alloc, unsigned int *added)
{
	struct richacl *acl = alloc->acl;
	unsigned int x = RICHACE_POSIX_ALWAYS_ALLOWED;
	unsigned int other_mask = acl->a_other_mask & ~x;
	struct richace *ace;

	if (!(other_mask &&
	      (acl->a_flags & RICHACL_WRITE_THROUGH)))
		return 0;

	*added = other_mask;
	ace = acl->a_entries + acl->a_count - 1;
	if (acl->a_count == 0 ||
	    !richace_is_everyone(ace) ||
	    richace_is_inherit_only(ace)) {
		ace++;
		if (richacl_insert_entry(alloc, &ace))
			return -1;
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = other_mask;
		ace->e_id.special = RICHACE_EVERYONE_SPECIAL_ID;
	} else {
		*added &= ~ace->e_mask;
		richace_change_mask(alloc, &ace, other_mask);
	}
	return 0;
}

/**
 * richacl_max_allowed  -  maximum permissions that anybody is allowed
 */
static unsigned int
richacl_max_allowed(struct richacl *acl)
{
	struct richace *ace;
	unsigned int allowed = 0;

	richacl_for_each_entry_reverse(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_allow(ace))
			allowed |= ace->e_mask;
		else if (richace_is_deny(ace)) {
			if (richace_is_everyone(ace))
				allowed &= ~ace->e_mask;
		}
	}
	return allowed;
}

/**
 * richacl_isolate_owner_class  -  limit the owner class to the owner file mask
 * @alloc:	acl and number of allocated entries
 *
 * POSIX requires that after a chmod, the owner class is granted no more
 * permissions than the owner file permission bits.  For richacls, this
 * means that the owner class must not be granted any permissions that the
 * owner mask does not include.
 *
 * When we apply file masks to an acl which grant more permissions to the group
 * or other class than to the owner class, we may end up in a situation where
 * the owner is granted additional permissions from other aces.  For example,
 * given this acl:
 *
 *    everyone@:rwx::allow
 *
 * when file masks corresponding to mode 0406 are applied, after
 * richacl_propagate_everyone() and __richacl_apply_masks(), we end up with:
 *
 *    owner@:r::allow
 *    everyone@:rw::allow
 *
 * This acl still grants the owner rw access through the everyone@ allow ace.
 * To fix this, we must deny the owner w access:
 *
 *    owner@:w::deny
 *    owner@:r::allow
 *    everyone@:rw::allow
 */
static int
richacl_isolate_owner_class(struct richacl_alloc *alloc)
{
	struct richacl *acl = alloc->acl;
	struct richace *ace;
	unsigned int deny;

	deny = richacl_max_allowed(acl) & ~acl->a_owner_mask;
	if (!deny)
		return 0;

	/*
	 * Figure out if we can update an existig OWNER@ DENY entry.
	 */
	richacl_for_each_entry(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_allow(ace))
			break;
		if (richace_is_owner(ace))
			return richace_change_mask(alloc, &ace,
						   ace->e_mask | deny);
	}

	/* Insert an owner@ deny entry at the front. */
	ace = acl->a_entries;
	if (richacl_insert_entry(alloc, &ace))
		return -1;
	ace->e_type = RICHACE_ACCESS_DENIED_ACE_TYPE;
	ace->e_flags = RICHACE_SPECIAL_WHO;
	ace->e_mask = deny;
	ace->e_id.special = RICHACE_OWNER_SPECIAL_ID;
	return 0;
}

/**
 * __richacl_isolate_who  -  isolate entry from everyone@ allow entry
 * @alloc:	acl and number of allocated entries
 * @who:	identifier to isolate
 * @deny:	permissions this identifier should not be allowed
 *
 * See richacl_isolate_group_class().
 */
static int
__richacl_isolate_who(struct richacl_alloc *alloc, struct richace *who,
		      unsigned int deny)
{
	struct richacl *acl = alloc->acl;
	struct richace *ace, who_copy;
	int n;

	/*
	 * Compute the permissions already defined for @who.  There are no
	 * everyone@ deny aces left in the acl at this stage.
	 */
	richacl_for_each_entry(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_same_identifier(ace, who))
			deny &= ~ace->e_mask;
	}
	if (!deny)
		return 0;

	/*
	 * Figure out if we can update an existig deny entry.  Start from the
	 * entry before the trailing everyone@ allow entry. We will not hit
	 * everyone@ entries in the loop.
	 */
	for (n = acl->a_count - 2; n != -1; n--) {
		ace = acl->a_entries + n;
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_deny(ace)) {
			if (richace_is_same_identifier(ace, who))
				return richace_change_mask(alloc, &ace,
							   ace->e_mask | deny);
		} else if (richace_is_allow(ace) &&
			   (ace->e_mask & deny))
			break;
	}

	/*
	 * Insert a new entry before the trailing everyone@ deny entry.
	 */
	richace_copy(&who_copy, who);
	ace = acl->a_entries + acl->a_count - 1;
	if (richacl_insert_entry(alloc, &ace))
		return -1;
	richace_copy(ace, &who_copy);
	ace->e_type = RICHACE_ACCESS_DENIED_ACE_TYPE;
	ace->e_flags &= ~RICHACE_INHERITANCE_FLAGS;
	ace->e_mask = deny;
	return 0;
}

/**
 * richacl_isolate_group_class  -  limit the group class to the group file mask
 * @alloc:	acl and number of allocated entries
 * @deny:	additional permissions to deny
 *
 * POSIX requires that after a chmod, the group class is granted no more
 * permissions than the group file permission bits.  For richacls, this
 * means that the group class must not be granted any permissions that the
 * group mask does not include.
 *
 * When we apply file masks to an acl which grant more permissions to the other
 * class than to the group class, we may end up in a situation where processes
 * in the group class are granted additional permission from other aces.  For
 * example, given this acl:
 *
 *    joe:rwx::allow
 *    everyone@:rwx::allow
 *
 * when file masks corresponding to mode 0646 are applied, after
 * richacl_propagate_everyone() and __richacl_apply_masks(), we end up with:
 *
 *    joe:r::allow
 *    owner@:rw::allow
 *    group@:r::allow
 *    everyone@:rw::allow
 *
 * This acl still grants joe and group@ rw access through the everyone@ allow
 * ace.  To fix this, we must deny w access to group class aces before the
 * everyone@ allow ace at the end of the acl:
 *
 *    joe:r::allow
 *    owner@:rw::allow
 *    group@:r::allow
 *    joe:w::deny
 *    group@:w::deny
 *    everyone@:rw::allow
 */
static int
richacl_isolate_group_class(struct richacl_alloc *alloc, unsigned int deny)
{
	struct richace who = {
		.e_flags = RICHACE_SPECIAL_WHO,
		.e_id.special = RICHACE_GROUP_SPECIAL_ID,
	};
	struct richace *ace;

	if (!alloc->acl->a_count)
		return 0;
	ace = alloc->acl->a_entries + alloc->acl->a_count - 1;
	if (richace_is_inherit_only(ace) || !richace_is_everyone(ace))
		return 0;
	deny |= ace->e_mask & ~alloc->acl->a_group_mask;

	if (deny) {
		unsigned int n;

		if (__richacl_isolate_who(alloc, &who, deny))
			return -1;
		/*
		 * Start from the entry before the trailing everyone@ allow
		 * entry.  We will not hit everyone@ entries in the loop.
		 */
		for (n = alloc->acl->a_count - 2; n != -1; n--) {
			ace = alloc->acl->a_entries + n;

			if (richace_is_inherit_only(ace) ||
			    richace_is_owner(ace) ||
			    richace_is_group(ace))
				continue;
			if (__richacl_isolate_who(alloc, ace, deny))
				return -1;
		}
	}
	return 0;
}

/**
 * __richacl_apply_masks  -  apply the file masks to all aces
 * @alloc:	acl and number of allocated entries
 *
 * Apply the owner mask to owner@ aces, the other mask to
 * everyone@ aces, and the group mask to all other aces.
 *
 * The previous transformations have brought the acl into a
 * form in which applying the masks will not lead to the
 * accidental loss of permissions anymore.
 */
static int
__richacl_apply_masks(struct richacl_alloc *alloc, kuid_t owner)
{
	struct richace *ace;

	richacl_for_each_entry(ace, alloc->acl) {
		unsigned int mask;

		if (richace_is_inherit_only(ace) || !richace_is_allow(ace))
			continue;
		if (richace_is_owner(ace) ||
		    (richace_is_unix_user(ace) && uid_eq(owner, ace->e_id.uid)))
			mask = alloc->acl->a_owner_mask;
		else if (richace_is_everyone(ace))
			mask = alloc->acl->a_other_mask;
		else
			mask = alloc->acl->a_group_mask;
		if (richace_change_mask(alloc, &ace, ace->e_mask & mask))
			return -1;
	}
	return 0;
}

/**
 * richacl_apply_masks  -  apply the masks to the acl
 *
 * Transform @acl so that the standard NFSv4 permission check algorithm (which
 * is not aware of file masks) will compute the same access decisions as the
 * richacl permission check algorithm (which looks at the acl and the file
 * masks).
 *
 * This algorithm is split into several steps:
 *
 *   - Move everyone@ aces to the end of the acl.  This simplifies the other
 *     transformations, and allows the everyone@ allow ace at the end of the
 *     acl to eventually allow permissions to the other class only.
 *
 *   - Propagate everyone@ permissions up the acl.  This transformation makes
 *     sure that the owner and group class aces won't lose any permissions when
 *     we apply the other mask to the everyone@ allow ace at the end of the acl.
 *
 *   - Apply the file masks to all aces.
 *
 *   - Make sure everyone is granted the other mask permissions.  This step can
 *     elevate elevate permissions for the owner and group classes, which is
 *     corrected later.
 *
 *   - Make sure that the group class is not granted any permissions from
 *     everyone@.
 *
 *   - Make sure the owner is granted the owner mask permissions.
 *
 *   - Make sure the owner is not granted any permissions beyond the owner
 *     mask from group class aces or from everyone@.
 *
 * NOTE: Depending on the acl and file masks, this algorithm can increase the
 * number of aces by almost a factor of three in the worst case. This may make
 * the acl too large for some purposes.
 */
int
richacl_apply_masks(struct richacl **acl, kuid_t owner)
{
	if ((*acl)->a_flags & RICHACL_MASKED) {
		struct richacl_alloc alloc = {
			.acl = richacl_clone(*acl, GFP_KERNEL),
			.count = (*acl)->a_count,
		};
		unsigned int added = 0;

		if (!alloc.acl)
			return -ENOMEM;
		if (richacl_move_everyone_aces_down(&alloc) ||
		    richacl_propagate_everyone(&alloc) ||
		    __richacl_apply_masks(&alloc, owner) ||
		    richacl_set_other_permissions(&alloc, &added) ||
		    richacl_isolate_group_class(&alloc, added) ||
		    richacl_set_owner_permissions(&alloc) ||
		    richacl_isolate_owner_class(&alloc)) {
			richacl_put(alloc.acl);
			return -ENOMEM;
		}

		alloc.acl->a_flags &= ~(RICHACL_WRITE_THROUGH | RICHACL_MASKED);
		richacl_put(*acl);
		*acl = alloc.acl;
	}
	return 0;
}
EXPORT_SYMBOL_GPL(richacl_apply_masks);

/**
 * richacl_from_mode  -  create an acl which corresponds to @mode
 *
 * The resulting acl doesn't have the RICHACL_MASKED flag set.
 *
 * @mode:	file mode including the file type
 */
struct richacl *
richacl_from_mode(umode_t mode)
{
	unsigned int owner_mask = richacl_mode_to_mask(mode >> 6);
	unsigned int group_mask = richacl_mode_to_mask(mode >> 3);
	unsigned int other_mask = richacl_mode_to_mask(mode);
	unsigned int denied;
	unsigned int entries = 0;
	struct richacl *acl;
	struct richace *ace;

	/* RICHACE_DELETE_CHILD is meaningless for non-directories. */
	if (!S_ISDIR(mode)) {
		owner_mask &= ~RICHACE_DELETE_CHILD;
		group_mask &= ~RICHACE_DELETE_CHILD;
		other_mask &= ~RICHACE_DELETE_CHILD;
	}

	denied = ~owner_mask & (group_mask | other_mask);
	if (denied)
		entries++;  /* owner@ deny entry needed */
	if (owner_mask & ~(group_mask & other_mask))
		entries++;  /* owner@ allow entry needed */
	denied = ~group_mask & other_mask;
	if (denied)
		entries++;  /* group@ deny entry needed */
	if (group_mask & ~other_mask)
		entries++;  /* group@ allow entry needed */
	if (other_mask)
		entries++;  /* everyone@ allow entry needed */

	acl = richacl_alloc(entries, GFP_KERNEL);
	if (!acl)
		return NULL;
	acl->a_owner_mask = owner_mask;
	acl->a_group_mask = group_mask;
	acl->a_other_mask = other_mask;
	ace = acl->a_entries;

	denied = ~owner_mask & (group_mask | other_mask);
	if (denied) {
		ace->e_type = RICHACE_ACCESS_DENIED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = denied;
		ace->e_id.special = RICHACE_OWNER_SPECIAL_ID;
		ace++;
	}
	if (owner_mask & ~(group_mask & other_mask)) {
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = owner_mask;
		ace->e_id.special = RICHACE_OWNER_SPECIAL_ID;
		ace++;
	}
	denied = ~group_mask & other_mask;
	if (denied) {
		ace->e_type = RICHACE_ACCESS_DENIED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = denied;
		ace->e_id.special = RICHACE_GROUP_SPECIAL_ID;
		ace++;
	}
	if (group_mask & ~other_mask) {
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = group_mask;
		ace->e_id.special = RICHACE_GROUP_SPECIAL_ID;
		ace++;
	}
	if (other_mask) {
		ace->e_type = RICHACE_ACCESS_ALLOWED_ACE_TYPE;
		ace->e_flags = RICHACE_SPECIAL_WHO;
		ace->e_mask = other_mask;
		ace->e_id.special = RICHACE_EVERYONE_SPECIAL_ID;
		ace++;
	}

	return acl;
}
EXPORT_SYMBOL_GPL(richacl_from_mode);
