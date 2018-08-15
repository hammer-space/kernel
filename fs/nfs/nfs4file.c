// SPDX-License-Identifier: GPL-2.0
/*
 *  linux/fs/nfs/file.c
 *
 *  Copyright (C) 1992  Rick Sladkey
 */
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/falloc.h>
#include <linux/nfs_fs.h>
#include "delegation.h"
#include "internal.h"
#include "iostat.h"
#include "fscache.h"
#include "pnfs.h"

#include "nfstrace.h"

#ifdef CONFIG_NFS_V4_2
#include "nfs42.h"
#endif

#define NFSDBG_FACILITY		NFSDBG_FILE

static int
nfs4_file_open(struct inode *inode, struct file *filp)
{
	struct nfs_open_context *ctx;
	struct dentry *dentry = file_dentry(filp);
	struct dentry *parent = NULL;
	struct inode *dir;
	unsigned openflags = filp->f_flags;
	struct iattr attr;
	int err;

	/*
	 * If no cached dentry exists or if it's negative, NFSv4 handled the
	 * opens in ->lookup() or ->create().
	 *
	 * We only get this far for a cached positive dentry.  We skipped
	 * revalidation, so handle it here by dropping the dentry and returning
	 * -EOPENSTALE.  The VFS will retry the lookup/create/open.
	 */

	dprintk("NFS: open file(%pd2)\n", dentry);

	err = nfs_check_flags(openflags);
	if (err)
		return err;

	if ((openflags & O_ACCMODE) == 3)
		openflags--;

	/* We can't create new files here */
	openflags &= ~(O_CREAT|O_EXCL);

	parent = dget_parent(dentry);
	dir = d_inode(parent);

	ctx = alloc_nfs_open_context(file_dentry(filp), filp->f_mode, filp);
	err = PTR_ERR(ctx);
	if (IS_ERR(ctx))
		goto out;

	attr.ia_valid = ATTR_OPEN;
	if (openflags & O_TRUNC) {
		attr.ia_valid |= ATTR_SIZE;
		attr.ia_size = 0;
		filemap_write_and_wait(inode->i_mapping);
	}

	inode = NFS_PROTO(dir)->open_context(dir, ctx, openflags, &attr, NULL);
	if (IS_ERR(inode)) {
		err = PTR_ERR(inode);
		switch (err) {
		case -EPERM:
		case -EACCES:
		case -EDQUOT:
		case -ENOSPC:
		case -EROFS:
			goto out_put_ctx;
		default:
			goto out_drop;
		}
	}
	if (inode != d_inode(dentry))
		goto out_drop;

	nfs_set_verifier(dentry, nfs_save_change_attribute(dir));
	nfs_file_set_open_context(filp, ctx);
	nfs_fscache_open_file(inode, filp);
	err = 0;

out_put_ctx:
	put_nfs_open_context(ctx);
out:
	dput(parent);
	return err;

out_drop:
	d_drop(dentry);
	err = -EOPENSTALE;
	goto out_put_ctx;
}

/*
 * Flush all dirty pages, and check for write errors.
 */
static int
nfs4_file_flush(struct file *file, fl_owner_t id)
{
	struct inode	*inode = file_inode(file);

	dprintk("NFS: flush(%pD2)\n", file);

	nfs_inc_stats(inode, NFSIOS_VFSFLUSH);
	if ((file->f_mode & FMODE_WRITE) == 0)
		return 0;

	/*
	 * If we're holding a write delegation, then check if we're required
	 * to flush the i/o on close. If not, then just start the i/o now.
	 */
	if (!nfs4_delegation_flush_on_close(inode))
		return filemap_fdatawrite(file->f_mapping);

	/* Flush writes to the server and return any errors */
	return vfs_fsync(file, 0);
}

static long nfs4_ioctl_file_statx_get(struct file *dst_file,
		struct nfs_ioctl_nfs4_statx __user *uarg)
{
	struct nfs_ioctl_nfs4_statx args = {
		.real_fd = -1,
		.fa_valid = { 0 },
	};
	struct inode *inode = file_inode(dst_file);
	struct nfs_server *server = NFS_SERVER(inode);
	u64 fattr_supported = server->fattr_valid;
	struct nfs_inode *nfsi = NFS_I(inode);
	int ret = -EFAULT;
	/*
	 * We get the first u64 word from the uarg as it tells us whether
	 * to use the passed in struct file or use that fd to find the
	 * struct file.
	 */
	if (get_user(args.real_fd, &uarg->real_fd))
		return -EFAULT;

	if (args.real_fd >= 0) {
		dst_file = fget_raw(args.real_fd);
		if (!dst_file)
			return -EBADF;
		inode = file_inode(dst_file);
		nfsi = NFS_I(inode);
	}

	ret = nfs_revalidate_inode(server, inode);
	if (ret != 0)
		return ret;

	if (fattr_supported & NFS_ATTR_FATTR_OWNER) {
		args.fa_valid[0] |= NFS_FA_VALID_OWNER;
		if (copy_to_user(&uarg->fa_owner_uid, &inode->i_uid, sizeof(uid_t)))
			goto out;
	}

	if (fattr_supported & NFS_ATTR_FATTR_GROUP) {
		args.fa_valid[0] |= NFS_FA_VALID_OWNER_GROUP;
		if (copy_to_user(&uarg->fa_group_gid, &inode->i_gid, sizeof(gid_t)))
			goto out;
	}

	if (fattr_supported & NFS_ATTR_FATTR_TIME_BACKUP) {
		args.fa_valid[0] |= NFS_FA_VALID_TIME_BACKUP;
		if (copy_to_user(&uarg->fa_time_backup, &nfsi->timebackup,
					sizeof(uarg->fa_time_backup)))
			goto out;
	}

	if (fattr_supported & NFS_ATTR_FATTR_TIME_CREATE) {
		args.fa_valid[0] |= NFS_FA_VALID_TIME_CREATE;
		if (copy_to_user(&uarg->fa_time_create, &nfsi->timecreate,
					sizeof(uarg->fa_time_create)))
			goto out;
	}

	/* atime, mtime, and ctime are all stored in the regular inode,
	 * not the nfs inode.
	 */
	if (fattr_supported & NFS_ATTR_FATTR_ATIME) {
		args.fa_valid[0] |= NFS_FA_VALID_ATIME;
		if (copy_to_user(&uarg->fa_atime, &inode->i_atime,
					sizeof(uarg->fa_atime)))
			goto out;
	}

	if (fattr_supported & NFS_ATTR_FATTR_MTIME) {
		args.fa_valid[0] |= NFS_FA_VALID_MTIME;
		if (copy_to_user(&uarg->fa_mtime, &inode->i_mtime,
					sizeof(uarg->fa_mtime)))
                        goto out;
	}

	if (fattr_supported & NFS_ATTR_FATTR_CTIME) {
		args.fa_valid[0] |= NFS_FA_VALID_CTIME;
		if (copy_to_user(&uarg->fa_ctime, &inode->i_ctime,
				sizeof(uarg->fa_ctime)))
			goto out;
	}

        /*
         * It looks like PDFS does not support or properly handle the 
         * archive bit.
         */
	if (fattr_supported & NFS_ATTR_FATTR_ARCHIVE) {
		args.fa_valid[0] |= NFS_FA_VALID_ARCHIVE;
		if (nfsi->archive)
			args.fa_flags |= NFS_FA_FLAG_ARCHIVE;
	}

	if (fattr_supported & NFS_ATTR_FATTR_TIME_BACKUP) {
		args.fa_valid[0] |= NFS_FA_VALID_ARCHIVE;
		if (timespec_compare(&nfsi->timebackup, &inode->i_mtime) >= 0)
			args.fa_flags |= NFS_FA_FLAG_ARCHIVE;
	}

	if (fattr_supported & NFS_ATTR_FATTR_HIDDEN) {
		args.fa_valid[0] |= NFS_FA_VALID_HIDDEN;
		if (nfsi->hidden)
			args.fa_flags |= NFS_FA_FLAG_HIDDEN;
	}
	if (fattr_supported & NFS_ATTR_FATTR_SYSTEM) {
		args.fa_valid[0] |= NFS_FA_VALID_SYSTEM;
		if (nfsi->system)
			args.fa_flags |= NFS_FA_FLAG_SYSTEM;
	}

	if (fattr_supported & NFS_ATTR_FATTR_OFFLINE) {
		args.fa_valid[0] |= NFS_FA_VALID_OFFLINE;
		if (nfsi->offline)
			args.fa_flags |= NFS_FA_FLAG_OFFLINE;
	}

	if ((args.fa_valid[0] & (NFS_FA_VALID_ARCHIVE |
				NFS_FA_VALID_HIDDEN |
				NFS_FA_VALID_SYSTEM |
				NFS_FA_VALID_OFFLINE)) &&
	    put_user(args.fa_flags, &uarg->fa_flags))
		goto out;

	if ((fattr_supported & NFS_ATTR_FATTR_MODE)) {
		args.fa_valid[0] |= NFS_FA_VALID_MODE;
		/* This is an unsigned short we put into an __u32 */
		if (copy_to_user(&uarg->fa_mode, &inode->i_mode,
				sizeof(unsigned short)))
			goto out;
	}

	if ((fattr_supported & NFS_ATTR_FATTR_NLINK)) {
		args.fa_valid[0] |= NFS_FA_VALID_NLINK;
		if (copy_to_user(&uarg->fa_nlink, &inode->i_nlink,
				sizeof(uarg->fa_nlink)))
			goto out;
	}

	args.fa_valid[0] |= NFS_FA_VALID_BLKSIZE;
	if (copy_to_user(&uarg->fa_blksize, &NFS_SERVER(inode)->dtsize,
			sizeof(uarg->fa_blksize)))
		goto out;

	args.fa_valid[0] |= NFS_FA_VALID_INO;
	if (copy_to_user(&uarg->fa_ino, &inode->i_ino,
			sizeof(uarg->fa_ino)))
		goto out;

	args.fa_valid[0] |= NFS_FA_VALID_DEV;
	if (copy_to_user(&uarg->fa_dev, &inode->i_sb->s_dev,
			sizeof(uarg->fa_dev)))
		goto out;

	if ((fattr_supported & NFS_ATTR_FATTR_RDEV)) {
		args.fa_valid[0] |= NFS_FA_VALID_RDEV;
		if (copy_to_user(&uarg->fa_rdev, &inode->i_rdev,
				sizeof(uarg->fa_rdev)))
			goto out;
	}

	if ((fattr_supported & NFS_ATTR_FATTR_SIZE)) {
		loff_t size = i_size_read(inode);
		args.fa_valid[0] |= NFS_FA_VALID_SIZE;
		if (copy_to_user(&uarg->fa_size, &size,
				sizeof(uarg->fa_size)))
			goto out;
	}

	if ((fattr_supported & NFS_ATTR_FATTR_BLOCKS_USED)) {
		args.fa_valid[0] |= NFS_FA_VALID_BLOCKS;
		if (copy_to_user(&uarg->fa_blocks, &inode->i_blocks,
				sizeof(uarg->fa_blocks)))
			goto out;
	}

	if (copy_to_user(uarg->fa_valid, args.fa_valid, sizeof(uarg->fa_valid)))
		goto out;

out:
	if (args.real_fd >= 0)
		fput(dst_file);
	return ret;
}

static long nfs4_ioctl_file_statx_set(struct file *dst_file,
		struct nfs_ioctl_nfs4_statx __user *uarg)
{
	struct inode *inode = file_inode(dst_file);
	struct nfs_ioctl_nfs4_statx args = {
		.real_fd = -1,
		.fa_valid = { 0 },
	};
	struct nfs_fattr *fattr = nfs_alloc_fattr();
	/*
	 * If you need a different error code below, you need to set it
	 */
	int ret = -EFAULT;

	if (fattr == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	/*
	 * We get the first u64 word from the uarg as it tells us whether
	 * to use the passed in struct file or use that fd to find the
	 * struct file.
	 */
	if (get_user(args.real_fd, &uarg->real_fd))
		goto out_free;

	if (args.real_fd >= 0) {
		dst_file = fget_raw(args.real_fd);
		if (!dst_file) {
			ret = -EBADF;
			goto out_free;
		}
		inode = file_inode(dst_file);
	}

	if (get_user(args.fa_valid[0], &uarg->fa_valid[0]))
		goto out;
	args.fa_valid[0] &= NFS_FA_VALID_ALL_ATTR_0;

	if ((args.fa_valid[0] & NFS_FA_VALID_OWNER) &&
	    copy_from_user(&args.fa_owner_uid, &uarg->fa_owner_uid,
					sizeof(args.fa_owner_uid)))
		goto out;

	if ((args.fa_valid[0] & NFS_FA_VALID_OWNER_GROUP) &&
	    copy_from_user(&args.fa_group_gid, &uarg->fa_group_gid,
					sizeof(args.fa_group_gid)))
		goto out;

	if ((args.fa_valid[0] & (NFS_FA_VALID_ARCHIVE |
					NFS_FA_VALID_HIDDEN |
					NFS_FA_VALID_SYSTEM)) &&
	    get_user(args.fa_flags, &uarg->fa_flags))
		goto out;

	if ((args.fa_valid[0] & NFS_FA_VALID_TIME_CREATE) &&
	    copy_from_user(&args.fa_time_create, &uarg->fa_time_create,
					sizeof(args.fa_time_create)))
		goto out;

	if ((args.fa_valid[0] & NFS_FA_VALID_ATIME) &&
	    copy_from_user(&args.fa_atime, &uarg->fa_atime,
					sizeof(args.fa_atime)))
		goto out;

	if ((args.fa_valid[0] & NFS_FA_VALID_MTIME) &&
	    copy_from_user(&args.fa_mtime, &uarg->fa_mtime,
					sizeof(args.fa_mtime)))
		goto out;

	if (args.fa_valid[0] & NFS_FA_VALID_TIME_BACKUP) {
		if (copy_from_user(&args.fa_time_backup, &uarg->fa_time_backup,
					sizeof(args.fa_time_backup)))
			goto out;
	} else if ((args.fa_valid[0] & NFS_FA_VALID_ARCHIVE) &&
			!(NFS_SERVER(inode)->fattr_valid & NFS_ATTR_FATTR_ARCHIVE)) {
		nfs_revalidate_inode(NFS_SERVER(inode), inode);
		args.fa_valid[0] |= NFS_FA_VALID_TIME_BACKUP;
		if (args.fa_flags & NFS_FA_FLAG_ARCHIVE)
			args.fa_time_backup = inode->i_mtime;
		else if (args.fa_valid[0] & NFS_FA_VALID_TIME_CREATE)
			args.fa_time_backup = args.fa_time_create;
		else
			args.fa_time_backup = NFS_I(inode)->timecreate;
	}

        if (args.fa_valid[0] & NFS_FA_VALID_SIZE) {
		if (copy_from_user(&args.fa_size, &uarg->fa_size,
					sizeof(args.fa_size)))
		goto out;
		/* Write all dirty data */
		if (S_ISREG(inode->i_mode))
			nfs_sync_inode(inode);
	}

	/*
	 * No need to update the inode because that is done in nfs4_set_nfs4_statx
	 */
	ret = nfs4_set_nfs4_statx(inode, &args, fattr);

out:
	if (args.real_fd >= 0)
		fput(dst_file);
out_free:
	nfs_free_fattr(fattr);
	return ret;
}

#ifdef CONFIG_NFS_V4_2
static ssize_t nfs4_copy_file_range(struct file *file_in, loff_t pos_in,
				    struct file *file_out, loff_t pos_out,
				    size_t count, unsigned int flags)
{
	if (file_inode(file_in) == file_inode(file_out))
		return -EINVAL;

	return nfs42_proc_copy(file_in, pos_in, file_out, pos_out, count);
}

static loff_t nfs4_file_llseek(struct file *filep, loff_t offset, int whence)
{
	loff_t ret;

	switch (whence) {
	case SEEK_HOLE:
	case SEEK_DATA:
		ret = nfs42_proc_llseek(filep, offset, whence);
		if (ret != -ENOTSUPP)
			return ret;
	default:
		return nfs_file_llseek(filep, offset, whence);
	}
}

static long nfs42_fallocate(struct file *filep, int mode, loff_t offset, loff_t len)
{
	struct inode *inode = file_inode(filep);
	long ret;

	if (!S_ISREG(inode->i_mode))
		return -EOPNOTSUPP;

	if ((mode != 0) && (mode != (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)))
		return -EOPNOTSUPP;

	ret = inode_newsize_ok(inode, offset + len);
	if (ret < 0)
		return ret;

	if (mode & FALLOC_FL_PUNCH_HOLE)
		return nfs42_proc_deallocate(filep, offset, len);
	return nfs42_proc_allocate(filep, offset, len);
}

static int nfs42_clone_file_range(struct file *src_file, loff_t src_off,
		struct file *dst_file, loff_t dst_off, u64 count)
{
	struct inode *dst_inode = file_inode(dst_file);
	struct nfs_server *server = NFS_SERVER(dst_inode);
	struct inode *src_inode = file_inode(src_file);
	unsigned int bs = server->clone_blksize;
	bool same_inode = false;
	int ret;

	/* check alignment w.r.t. clone_blksize */
	ret = -EINVAL;
	if (bs) {
		if (!IS_ALIGNED(src_off, bs) || !IS_ALIGNED(dst_off, bs))
			goto out;
		if (!IS_ALIGNED(count, bs) && i_size_read(src_inode) != (src_off + count))
			goto out;
	}

	if (src_inode == dst_inode)
		same_inode = true;

	/* XXX: do we lock at all? what if server needs CB_RECALL_LAYOUT? */
	if (same_inode) {
		inode_lock(src_inode);
	} else if (dst_inode < src_inode) {
		inode_lock_nested(dst_inode, I_MUTEX_PARENT);
		inode_lock_nested(src_inode, I_MUTEX_CHILD);
	} else {
		inode_lock_nested(src_inode, I_MUTEX_PARENT);
		inode_lock_nested(dst_inode, I_MUTEX_CHILD);
	}

	/* flush all pending writes on both src and dst so that server
	 * has the latest data */
	ret = nfs_sync_inode(src_inode);
	if (ret)
		goto out_unlock;
	ret = nfs_sync_inode(dst_inode);
	if (ret)
		goto out_unlock;

	ret = nfs42_proc_clone(src_file, dst_file, src_off, dst_off, count);

	/* truncate inode page cache of the dst range so that future reads can fetch
	 * new data from server */
	if (!ret)
		truncate_inode_pages_range(&dst_inode->i_data, dst_off, dst_off + count - 1);

out_unlock:
	if (same_inode) {
		inode_unlock(src_inode);
	} else if (dst_inode < src_inode) {
		inode_unlock(src_inode);
		inode_unlock(dst_inode);
	} else {
		inode_unlock(dst_inode);
		inode_unlock(src_inode);
	}
out:
	return ret;
}

static long nfs4_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	long ret;

	switch (cmd) {
	case NFS_IOC_FILE_STATX_GET:
		ret = nfs4_ioctl_file_statx_get(file, argp);
		break;
	case NFS_IOC_FILE_STATX_SET:
		ret = nfs4_ioctl_file_statx_set(file, argp);
		break;
	default:
		ret = -ENOIOCTLCMD;
	}

	dprintk("%s: file=%pD2, cmd=%u, ret=%ld\n", __func__, file, cmd, ret);
	return ret;
}

#endif /* CONFIG_NFS_V4_2 */

const struct file_operations nfs4_file_operations = {
	.read_iter	= nfs_file_read,
	.write_iter	= nfs_file_write,
	.mmap		= nfs_file_mmap,
	.open		= nfs4_file_open,
	.flush		= nfs4_file_flush,
	.release	= nfs_file_release,
	.fsync		= nfs_file_fsync,
	.lock		= nfs_lock,
	.flock		= nfs_flock,
	.splice_read	= generic_file_splice_read,
	.splice_write	= iter_file_splice_write,
	.check_flags	= nfs_check_flags,
	.setlease	= simple_nosetlease,
#ifdef CONFIG_NFS_V4_2
	.copy_file_range = nfs4_copy_file_range,
	.llseek		= nfs4_file_llseek,
	.fallocate	= nfs42_fallocate,
	.unlocked_ioctl	= nfs4_ioctl,
	.clone_file_range = nfs42_clone_file_range,
#else
	.llseek		= nfs_file_llseek,
#endif
};

const struct file_operations nfs4_dir_operations = {
	.llseek		= nfs_llseek_dir,
	.read		= generic_read_dir,
	.iterate	= nfs_readdir,
	.open		= nfs_opendir,
	.release	= nfs_closedir,
	.fsync		= nfs_fsync_dir,
	.unlocked_ioctl = nfs4_ioctl,
};
