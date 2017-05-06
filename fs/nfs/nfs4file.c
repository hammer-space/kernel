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
		return nfs_open(inode, filp);

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
		.fa_valid = { 0 },
	};
	struct inode *inode = file_inode(dst_file);
	struct nfs_server *server = NFS_SERVER(inode);
	struct nfs_inode *nfsi = NFS_I(inode);
	int ret;

	ret = nfs_revalidate_inode(server, inode);
	if (ret != 0)
		return ret;

	if (nfs_server_capable(inode, NFS_CAP_TIME_BACKUP)) {
		args.fa_valid[0] |= NFS_FA_VALID_TIME_BACKUP;
		if (copy_to_user(&uarg->fa_time_backup, &nfsi->timebackup,
					sizeof(uarg->fa_time_backup)))
			ret = EFAULT;
	}

	if (nfs_server_capable(inode, NFS_CAP_TIME_CREATE)) {
		args.fa_valid[0] |= NFS_FA_VALID_TIME_BACKUP;
		if (copy_to_user(&uarg->fa_time_create, &nfsi->timecreate,
					sizeof(uarg->fa_time_create)))
			ret = -EFAULT;
	}

	if (nfs_server_capable(inode, NFS_CAP_ARCHIVE)) {
		args.fa_valid[0] |= NFS_FA_VALID_ARCHIVE;
		if (nfsi->archive)
			args.fa_flags |= NFS_FA_FLAG_ARCHIVE;
	} else if (nfs_server_capable(inode, NFS_CAP_TIME_BACKUP)) {
		struct timespec ts = timespec64_to_timespec(inode->i_mtime);
		args.fa_valid[0] |= NFS_FA_VALID_ARCHIVE;
		if (timespec_compare(&nfsi->timebackup, &ts) >= 0)
			args.fa_flags |= NFS_FA_FLAG_ARCHIVE;
	}

	if (nfs_server_capable(inode, NFS_CAP_HIDDEN)) {
		args.fa_valid[0] |= NFS_FA_VALID_HIDDEN;
		if (nfsi->hidden)
			args.fa_flags |= NFS_FA_FLAG_HIDDEN;
	}
	if (nfs_server_capable(inode, NFS_CAP_SYSTEM)) {
		args.fa_valid[0] |= NFS_FA_VALID_SYSTEM;
		if (nfsi->system)
			args.fa_flags |= NFS_FA_FLAG_SYSTEM;
	}

	if ((args.fa_valid[0] & (NFS_FA_VALID_ARCHIVE |
				NFS_FA_VALID_HIDDEN |
				NFS_FA_VALID_SYSTEM)) &&
	    put_user(args.fa_flags, &uarg->fa_flags))
		ret = -EFAULT;

	if (copy_to_user(uarg->fa_valid, args.fa_valid, sizeof(uarg->fa_valid)))
		ret = -EFAULT;

	return ret;
}

static long nfs4_ioctl_file_statx_set(struct file *dst_file,
		struct nfs_ioctl_nfs4_statx __user *uarg)
{
	struct inode *inode = file_inode(dst_file);
	struct nfs_ioctl_nfs4_statx args = {
		.fa_valid = { 0 },
	};
	struct nfs_fattr *fattr = nfs_alloc_fattr();
	int ret;

	if (fattr == NULL)
		return -ENOMEM;
	if (get_user(args.fa_valid[0], &uarg->fa_valid[0]))
		return -EFAULT;
	args.fa_valid[0] &= NFS_FA_VALID_ALL_ATTR_0;

	if ((args.fa_valid[0] & (NFS_FA_VALID_ARCHIVE |
					NFS_FA_VALID_HIDDEN |
					NFS_FA_VALID_SYSTEM)) &&
	    get_user(args.fa_flags, &uarg->fa_flags))
		return -EFAULT;

	if ((args.fa_valid[0] & NFS_FA_VALID_TIME_CREATE) &&
	    copy_from_user(&args.fa_time_create, &uarg->fa_time_create,
					sizeof(args.fa_time_create)))
		return -EFAULT;

	if (args.fa_valid[0] & NFS_FA_VALID_TIME_BACKUP) {
		if (copy_from_user(&args.fa_time_backup, &uarg->fa_time_backup,
					sizeof(args.fa_time_backup)))
			return -EFAULT;
		if (!(args.fa_valid[0] & NFS_FA_VALID_ARCHIVE)) {
			args.fa_valid[0] |= NFS_FA_VALID_ARCHIVE;
			args.fa_flags |= NFS_FA_FLAG_ARCHIVE;
		}
	} else if (args.fa_valid[0] & NFS_FA_VALID_ARCHIVE) {
		args.fa_time_backup = current_kernel_time();
		args.fa_valid[0] |= NFS_FA_VALID_TIME_BACKUP;
	}

	ret = nfs4_set_nfs4_statx(inode, &args, fattr);
	if (ret == 0)
		nfs_post_op_update_inode(inode, fattr);

	return ret;
}

#ifdef CONFIG_NFS_V4_2
static ssize_t nfs4_copy_file_range(struct file *file_in, loff_t pos_in,
				    struct file *file_out, loff_t pos_out,
				    size_t count, unsigned int flags)
{
	if (!nfs_server_capable(file_inode(file_out), NFS_CAP_COPY))
		return -EOPNOTSUPP;
	if (file_inode(file_in) == file_inode(file_out))
		return -EOPNOTSUPP;
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
		/* Fall through */
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

static loff_t nfs42_remap_file_range(struct file *src_file, loff_t src_off,
		struct file *dst_file, loff_t dst_off, loff_t count,
		unsigned int remap_flags)
{
	struct inode *dst_inode = file_inode(dst_file);
	struct nfs_server *server = NFS_SERVER(dst_inode);
	struct inode *src_inode = file_inode(src_file);
	unsigned int bs = server->clone_blksize;
	bool same_inode = false;
	int ret;

	if (remap_flags & ~(REMAP_FILE_DEDUP | REMAP_FILE_ADVISORY))
		return -EINVAL;

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
	return ret < 0 ? ret : count;
}

static long nfs4_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	case NFS_IOC_FILE_STATX_GET:
		return nfs4_ioctl_file_statx_get(file, argp);
	case NFS_IOC_FILE_STATX_SET:
		return nfs4_ioctl_file_statx_set(file, argp);
	}

	return -ENOTTY;
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
	.remap_file_range = nfs42_remap_file_range,
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
