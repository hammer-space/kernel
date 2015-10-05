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

#include <linux/cred.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/module.h>
#include <linux/xattr.h>
#include <linux/richacl_xattr.h>
#include <uapi/linux/xattr.h>

/**
 * richacl_from_xattr  -  convert a richacl xattr into the in-memory representation
 */
struct richacl *
richacl_from_xattr(struct user_namespace *user_ns,
		   const void *value, size_t size, int invalid_error)
{
	const struct richacl_xattr *xattr_acl = value;
	const struct richace_xattr *xattr_ace = (void *)(xattr_acl + 1);
	struct richacl *acl;
	struct richace *ace;
	int count;

	if (size < sizeof(*xattr_acl) ||
	    xattr_acl->a_version != RICHACL_XATTR_VERSION ||
	    (xattr_acl->a_flags & ~RICHACL_VALID_FLAGS))
		goto invalid;
	size -= sizeof(*xattr_acl);
	count = le16_to_cpu(xattr_acl->a_count);
	if (count > RICHACL_XATTR_MAX_COUNT)
		goto invalid;
	if (size != count * sizeof(*xattr_ace))
		goto invalid;

	acl = richacl_alloc(count, GFP_NOFS);
	if (!acl)
		return ERR_PTR(-ENOMEM);

	acl->a_flags = xattr_acl->a_flags;
	acl->a_owner_mask = le32_to_cpu(xattr_acl->a_owner_mask);
	if (acl->a_owner_mask & ~RICHACE_VALID_MASK)
		goto put_invalid;
	acl->a_group_mask = le32_to_cpu(xattr_acl->a_group_mask);
	if (acl->a_group_mask & ~RICHACE_VALID_MASK)
		goto put_invalid;
	acl->a_other_mask = le32_to_cpu(xattr_acl->a_other_mask);
	if (acl->a_other_mask & ~RICHACE_VALID_MASK)
		goto put_invalid;

	richacl_for_each_entry(ace, acl) {
		ace->e_type  = le16_to_cpu(xattr_ace->e_type);
		ace->e_flags = le16_to_cpu(xattr_ace->e_flags);
		ace->e_mask  = le32_to_cpu(xattr_ace->e_mask);

		if (ace->e_flags & ~RICHACE_VALID_FLAGS)
			goto put_invalid;
		if (ace->e_flags & RICHACE_SPECIAL_WHO) {
			ace->e_id.special = le32_to_cpu(xattr_ace->e_id);
			if (ace->e_id.special > RICHACE_EVERYONE_SPECIAL_ID)
				goto put_invalid;
		} else if (ace->e_flags & RICHACE_IDENTIFIER_GROUP) {
			u32 id = le32_to_cpu(xattr_ace->e_id);

			ace->e_id.gid = make_kgid(user_ns, id);
			if (!gid_valid(ace->e_id.gid))
				goto put_invalid;
		} else {
			u32 id = le32_to_cpu(xattr_ace->e_id);

			ace->e_id.uid = make_kuid(user_ns, id);
			if (!uid_valid(ace->e_id.uid))
				goto put_invalid;
		}
		if (ace->e_type > RICHACE_ACCESS_DENIED_ACE_TYPE ||
		    (ace->e_mask & ~RICHACE_VALID_MASK))
			goto put_invalid;

		xattr_ace++;
	}

	return acl;

put_invalid:
	richacl_put(acl);
invalid:
	return ERR_PTR(invalid_error);
}
EXPORT_SYMBOL_GPL(richacl_from_xattr);

/**
 * richacl_xattr_size  -  compute the size of the xattr representation of @acl
 */
size_t
richacl_xattr_size(const struct richacl *acl)
{
	size_t size = sizeof(struct richacl_xattr);

	size += sizeof(struct richace_xattr) * acl->a_count;
	return size;
}
EXPORT_SYMBOL_GPL(richacl_xattr_size);

/**
 * richacl_to_xattr  -  convert @acl into its xattr representation
 * @acl:	the richacl to convert
 * @buffer:	buffer for the result
 * @size:	size of @buffer
 */
int
richacl_to_xattr(struct user_namespace *user_ns,
		 const struct richacl *acl, void *buffer, size_t size)
{
	struct richacl_xattr *xattr_acl = buffer;
	struct richace_xattr *xattr_ace;
	const struct richace *ace;
	size_t real_size;

	real_size = richacl_xattr_size(acl);
	if (!buffer)
		return real_size;
	if (real_size > size)
		return -ERANGE;

	xattr_acl->a_version = RICHACL_XATTR_VERSION;
	xattr_acl->a_flags = acl->a_flags;
	xattr_acl->a_count = cpu_to_le16(acl->a_count);

	xattr_acl->a_owner_mask = cpu_to_le32(acl->a_owner_mask);
	xattr_acl->a_group_mask = cpu_to_le32(acl->a_group_mask);
	xattr_acl->a_other_mask = cpu_to_le32(acl->a_other_mask);

	xattr_ace = (void *)(xattr_acl + 1);
	richacl_for_each_entry(ace, acl) {
		xattr_ace->e_type = cpu_to_le16(ace->e_type);
		xattr_ace->e_flags = cpu_to_le16(ace->e_flags);
		xattr_ace->e_mask = cpu_to_le32(ace->e_mask);
		if (ace->e_flags & RICHACE_SPECIAL_WHO)
			xattr_ace->e_id = cpu_to_le32(ace->e_id.special);
		else if (ace->e_flags & RICHACE_IDENTIFIER_GROUP)
			xattr_ace->e_id =
				cpu_to_le32(from_kgid(user_ns, ace->e_id.gid));
		else
			xattr_ace->e_id =
				cpu_to_le32(from_kuid(user_ns, ace->e_id.uid));
		xattr_ace++;
	}
	return real_size;
}
EXPORT_SYMBOL_GPL(richacl_to_xattr);

static bool
richacl_xattr_list(struct dentry *dentry)
{
	return IS_RICHACL(d_backing_inode(dentry));
}

static int
richacl_xattr_get(const struct xattr_handler *handler,
		  struct dentry *dentry, struct inode *inode,
		  const char *name, void *buffer,
		  size_t buffer_size)
{
	struct richacl *acl;
	int error;

	if (*name)
		return -EINVAL;
	if (!IS_RICHACL(inode))
		return -EOPNOTSUPP;
	if (S_ISLNK(inode->i_mode))
		return -EOPNOTSUPP;
	acl = get_richacl(inode);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	if (acl == NULL)
		return -ENODATA;
	error = richacl_to_xattr(current_user_ns(), acl, buffer, buffer_size);
	richacl_put(acl);
	return error;
}

static int
richacl_xattr_set(const struct xattr_handler *handler,
		  struct dentry *dentry, struct inode *inode,
		  const char *name, const void *value,
		  size_t size, int flags)
{
	struct richacl *acl = NULL;
	int ret;

	if (*name)
		return -EINVAL;
	if (!IS_RICHACL(inode))
		return -EOPNOTSUPP;
	if (!inode->i_op->set_richacl)
		return -EOPNOTSUPP;

	if (!uid_eq(current_fsuid(), inode->i_uid) &&
	    inode_permission(inode, MAY_CHMOD) &&
	    !capable(CAP_FOWNER))
		return -EPERM;

	if (value) {
		acl = richacl_from_xattr(current_user_ns(), value, size,
					 -EINVAL);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
	}

	ret = inode->i_op->set_richacl(inode, acl);
	richacl_put(acl);
	return ret;
}

struct xattr_handler richacl_xattr_handler = {
	.name = XATTR_NAME_RICHACL,
	.list = richacl_xattr_list,
	.get = richacl_xattr_get,
	.set = richacl_xattr_set,
};
EXPORT_SYMBOL(richacl_xattr_handler);
