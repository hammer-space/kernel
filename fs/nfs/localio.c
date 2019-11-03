/*
 *  linux/fs/nfs/localio.c
 *
 *  Copyright (C) 2014  Weston Andros Adamson <dros@primarydata.com>
 *
 */

#include <linux/module.h>
#include <linux/errno.h>
#include <linux/vfs.h>
#include <linux/file.h>
#include <linux/inet.h>
#include <linux/sunrpc/addr.h>
#include <linux/inetdevice.h>
#include <net/addrconf.h>
#include <linux/module.h>
#include <linux/bvec.h>

#include <linux/nfs.h>
#include <linux/nfs_fs.h>
#include <linux/nfs_xdr.h>

#include "internal.h"
#include "pnfs.h"
#include "nfstrace.h"

#define NFSDBG_FACILITY		NFSDBG_VFS

/*
 * The localio code needs to call into nfsd to do the filehandle -> struct path
 * mapping, but cannot be statically linked, because that will make the nfs
 * module depend on the nfsd module.
 *
 * Instead, do dynamic linking to the nfsd module. This way the nfs module
 * will only hold a reference on nfsd when it's actually in use. This also
 * allows some sanity checking, like giving up on localio if nfsd isn't loaded.
 */

struct nfs_local_open_ctx {
	spinlock_t lock;
	nfs_to_nfsd_open_t open_f;
	struct module *mod;
	atomic_t refcount;
};

struct nfs_local_kiocb {
	struct kiocb		kiocb;
	struct bio_vec		*bvec;
	struct nfs_pgio_header	*hdr;
	struct work_struct	work;
};

/*
 * We need to translate between nfs status return values and
 * the local errno values which may not be the same.
 */
static struct {
	__u32 stat;
	int errno;
} nfs_errtbl[] = {
	{ NFS4_OK,		0		},
	{ NFS4ERR_PERM,		-EPERM		},
	{ NFS4ERR_NOENT,	-ENOENT		},
	{ NFS4ERR_IO,		-EIO		},
	{ NFS4ERR_NXIO,		-ENXIO		},
	{ NFS4ERR_FBIG,		-E2BIG		},
	{ NFS4ERR_STALE,	-EBADF		},
	{ NFS4ERR_ACCESS,	-EACCES		},
	{ NFS4ERR_EXIST,	-EEXIST		},
	{ NFS4ERR_XDEV,		-EXDEV		},
	{ NFS4ERR_MLINK,	-EMLINK		},
	{ NFS4ERR_NOTDIR,	-ENOTDIR	},
	{ NFS4ERR_ISDIR,	-EISDIR		},
	{ NFS4ERR_INVAL,	-EINVAL		},
	{ NFS4ERR_FBIG,		-EFBIG		},
	{ NFS4ERR_NOSPC,	-ENOSPC		},
	{ NFS4ERR_ROFS,		-EROFS		},
	{ NFS4ERR_NAMETOOLONG,	-ENAMETOOLONG	},
	{ NFS4ERR_NOTEMPTY,	-ENOTEMPTY	},
	{ NFS4ERR_DQUOT,	-EDQUOT		},
	{ NFS4ERR_STALE,	-ESTALE		},
	{ NFS4ERR_STALE,	-EOPENSTALE	},
	{ NFS4ERR_DELAY,	-ETIMEDOUT	},
	{ NFS4ERR_DELAY,	-ERESTARTSYS	},
	{ NFS4ERR_DELAY,	-EAGAIN		},
	{ NFS4ERR_DELAY,	-ENOMEM		},
	{ NFS4ERR_IO,		-ETXTBSY	},
	{ NFS4ERR_IO,		-EBUSY		},
	{ NFS4ERR_BADHANDLE,	-EBADHANDLE	},
	{ NFS4ERR_BAD_COOKIE,	-EBADCOOKIE	},
	{ NFS4ERR_NOTSUPP,	-EOPNOTSUPP	},
	{ NFS4ERR_TOOSMALL,	-ETOOSMALL	},
	{ NFS4ERR_SERVERFAULT,	-ESERVERFAULT	},
	{ NFS4ERR_SERVERFAULT,	-ENFILE		},
	{ NFS4ERR_IO,		-EREMOTEIO	},
	{ NFS4ERR_IO,		-EUCLEAN	},
	{ NFS4ERR_PERM,		-ENOKEY		},
	{ NFS4ERR_BADTYPE,	-EBADTYPE	},
	{ NFS4ERR_SYMLINK,	-ELOOP		},
	{ NFS4ERR_DEADLOCK,	-EDEADLK	},
};

/*
 * Convert an NFS error code to a local one.
 * This one is used jointly by NFSv2 and NFSv3.
 */
static __u32
nfs4errno(int errno)
{
	unsigned int i;
	for (i = 0; i < ARRAY_SIZE(nfs_errtbl); i++) {
		if (nfs_errtbl[i].errno == errno)
			return nfs_errtbl[i].stat;
	}
	/* If we cannot translate the error, the recovery routines should
	 * handle it.
	 * Note: remaining NFSv4 error codes have values > 10000, so should
	 * not conflict with native Linux error codes.
	 */
	return NFS4ERR_SERVERFAULT;
}

static struct nfs_local_open_ctx __local_open_ctx __read_mostly;

static bool localio_enabled __read_mostly = true;
module_param(localio_enabled, bool, 0644);

static bool localio_datasync __read_mostly;
module_param(localio_datasync, bool, 0644);

bool nfs_server_is_local(const struct nfs_client *clp)
{
	return test_bit(NFS_CS_LOCAL_IO, &clp->cl_flags) != 0 &&
		localio_enabled;
}
EXPORT_SYMBOL_GPL(nfs_server_is_local);

void
nfs_local_init(void)
{
	struct nfs_local_open_ctx *ctx = &__local_open_ctx;

	ctx->open_f = NULL;
	ctx->mod = NULL;
	spin_lock_init(&ctx->lock);
	atomic_set(&ctx->refcount, 0);
}

static bool
nfs_local_get_lookup_ctx(void)
{
	struct nfs_local_open_ctx *ctx = &__local_open_ctx;
	const s32 *crc = NULL;
	struct module *mod;
	const struct kernel_symbol *sym;

	atomic_inc(&ctx->refcount);

	spin_lock(&ctx->lock);
	if (ctx->open_f == NULL) {
		spin_unlock(&ctx->lock);

		mutex_lock(&module_mutex);
		mod = find_module("nfsd");
		if (!mod || !try_module_get(mod)) {
			mutex_unlock(&module_mutex);
			goto out_bad;
		}
		sym = find_symbol("nfsd_open_local_fh", &ctx->mod, &crc,
				  true, true);
		mutex_unlock(&module_mutex);
		if (!sym)
			goto out_bad_put;

		dprintk("create lookup context %lu\n", kernel_symbol_value(sym));

		spin_lock(&ctx->lock);

		/* catch race */
		if (ctx->open_f != NULL)
			goto out_bad_unlock;

		ctx->open_f = (nfs_to_nfsd_open_t) kernel_symbol_value(sym);
		ctx->mod = mod;
	}
	spin_unlock(&ctx->lock);

	return true;

out_bad_unlock:
	spin_unlock(&ctx->lock);
out_bad_put:
	module_put(mod);
out_bad:
	atomic_dec(&ctx->refcount);
	return false;
}

static void
nfs_local_put_lookup_ctx(void)
{
	struct nfs_local_open_ctx *ctx = &__local_open_ctx;
	struct module *mod;

	if (atomic_dec_and_lock(&ctx->refcount, &ctx->lock)) {
		ctx->open_f = NULL;
		mod = ctx->mod;
		ctx->mod = NULL;
		spin_unlock(&ctx->lock);
		module_put(mod);
		dprintk("destroy lookup context\n");
	}
}

/*
 * nfs_local_enable - attempt to enable local i/o for an nfs_client
 */
void
nfs_local_enable(struct nfs_client *clp)
{
	if (nfs_local_get_lookup_ctx()) {
		dprintk("enabled local i/o\n");
		set_bit(NFS_CS_LOCAL_IO, &clp->cl_flags);
	}
}
EXPORT_SYMBOL_GPL(nfs_local_enable);

/*
 * nfs_local_disable - disable local i/o for an nfs_client
 */
void
nfs_local_disable(struct nfs_client *clp)
{
	if (test_and_clear_bit(NFS_CS_LOCAL_IO, &clp->cl_flags)) {
		dprintk("disabled local i/o\n");
		nfs_local_put_lookup_ctx();
	}
}
EXPORT_SYMBOL_GPL(nfs_local_disable);

/*
 * nfs_local_probe - probe local i/o support for an nfs_client
 */
void
nfs_local_probe(struct nfs_client *clp)
{
	struct sockaddr_in *sin;
	struct sockaddr_in6 *sin6;
	struct nfs_local_addr *addr;
	struct sockaddr *sap;
	bool enable = false;

	switch (clp->cl_addr.ss_family) {
	case AF_INET:
		sin = (struct sockaddr_in *)&clp->cl_addr;
		if (ipv4_is_loopback(sin->sin_addr.s_addr)) {
			dprintk("%s: detected IPv4 loopback address\n",
				__func__);
			enable = true;
		}
		break;
	case AF_INET6:
		sin6 = (struct sockaddr_in6 *)&clp->cl_addr;
		if (memcmp(&sin6->sin6_addr, &in6addr_loopback,
		    sizeof(struct in6_addr)) == 0) {
			dprintk("%s: detected IPv6 loopback address\n",
				__func__);
			enable = true;
		}
		break;
	default:
		break;
	}

	if (enable)
		goto out;

	list_for_each_entry(addr, &clp->cl_local_addrs, cl_addrs) {
		sap = (struct sockaddr *)&addr->address;
		if (rpc_cmp_addr((struct sockaddr *)&clp->cl_addr, sap)) {
			dprintk("%s: detected local server.\n", __func__);
			enable = true;
			break;
		}
	}

out:
	if (enable)
		nfs_local_enable(clp);
}
EXPORT_SYMBOL_GPL(nfs_local_probe);

/*
 * nfs_local_open_fh - open a local filehandle
 *
 * Returns a pointer to a struct file or an ERR_PTR
 */
struct file *
nfs_local_open_fh(struct nfs_client *clp, const struct cred *cred,
		  struct nfs_fh *fh, const fmode_t mode)
{
	struct nfs_local_open_ctx *ctx = &__local_open_ctx;
	struct file *filp;
	int flags = O_LARGEFILE;
	int status;

	switch (mode & (FMODE_READ | FMODE_WRITE)) {
	case FMODE_READ | FMODE_WRITE:
		flags |= O_RDWR;
		break;
	case FMODE_READ:
		flags |= O_RDONLY;
		break;
	case FMODE_WRITE:
		flags |= O_WRONLY;
		break;
	default:
		return ERR_PTR(-EINVAL);
	}

	status = ctx->open_f(clp->cl_rpcclient, cred, fh, mode, &filp);
	if (status < 0) {
		dprintk("%s: open local file failed error=%d\n",
				__func__, status);
		trace_nfs_local_open_fh(fh, mode, status);
		switch (status) {
		case -ENXIO:
			nfs_local_disable(clp);
			/* Fallthrough */
		case -ETIMEDOUT:
			status = -EAGAIN;
		}
		filp = ERR_PTR(status);
	}
	return filp;
}
EXPORT_SYMBOL_GPL(nfs_local_open_fh);

static struct bio_vec *
nfs_bvec_alloc_and_import_pagevec(struct page **pagevec,
		unsigned int npages, gfp_t flags)
{
	struct bio_vec *bvec, *p;

	bvec = kmalloc_array(npages, sizeof(*bvec), flags);
	if (bvec != NULL) {
		for (p = bvec; npages > 0; p++, pagevec++, npages--) {
			p->bv_page = *pagevec;
			p->bv_len = PAGE_SIZE;
			p->bv_offset = 0;
		}
	}
	return bvec;
}

static void
nfs_local_iocb_free(struct nfs_local_kiocb *iocb)
{
	kfree(iocb->bvec);
	kfree(iocb);
}

static struct nfs_local_kiocb *
nfs_local_iocb_alloc(struct nfs_pgio_header *hdr, struct file *filp,
		gfp_t flags)
{
	struct nfs_local_kiocb *iocb;

	iocb = kmalloc(sizeof(*iocb), flags);
	if (iocb == NULL)
		return NULL;
	iocb->bvec = nfs_bvec_alloc_and_import_pagevec(hdr->page_array.pagevec,
			hdr->page_array.npages, flags);
	if (iocb->bvec == NULL) {
		kfree(iocb);
		return NULL;
	}
	init_sync_kiocb(&iocb->kiocb, filp);
	iocb->kiocb.ki_pos = hdr->args.offset;
	iocb->hdr = hdr;
	if (test_bit(NFS_IOHDR_ODIRECT, &hdr->flags))
		iocb->kiocb.ki_flags |= IOCB_DIRECT|IOCB_DSYNC;
	iocb->kiocb.ki_flags &= ~IOCB_APPEND;
	return iocb;
}

static void
nfs_local_iter_init(struct iov_iter *i, struct nfs_local_kiocb *iocb, int dir)
{
	struct nfs_pgio_header *hdr = iocb->hdr;

	if (hdr->args.pgbase != 0) {
		iov_iter_bvec(i, dir, iocb->bvec,
				hdr->page_array.npages,
				hdr->args.count + hdr->args.pgbase);
		iov_iter_advance(i, hdr->args.pgbase);
	} else
		iov_iter_bvec(i, dir, iocb->bvec,
				hdr->page_array.npages, hdr->args.count);
	i->type |= ITER_BVEC_FLAG_NO_REF;
}

static void
nfs_local_pgio_init(struct nfs_pgio_header *hdr,
		const struct rpc_call_ops *call_ops)
{
	hdr->task.tk_ops = call_ops;
	if (!hdr->task.tk_start)
		hdr->task.tk_start = ktime_get();
}

static void
nfs_local_pgio_done(struct nfs_pgio_header *hdr, long status)
{
	if (status >= 0) {
		hdr->res.count = status;
		hdr->res.op_status = NFS4_OK;
		hdr->task.tk_status = 0;
	} else {
		hdr->res.op_status = nfs4errno(status);
		hdr->task.tk_status = status;
	}
}

static void
nfs_local_pgio_complete_work(struct work_struct *work)
{
	struct nfs_local_kiocb *iocb = container_of(work,
			struct nfs_local_kiocb, work);
	struct nfs_pgio_header *hdr = iocb->hdr;
	const struct rpc_call_ops *call_ops = hdr->task.tk_ops;

	fput(iocb->kiocb.ki_filp);
	nfs_local_iocb_free(iocb);
	call_ops->rpc_call_done(&hdr->task, hdr);
	call_ops->rpc_release(hdr);
}

/*
 * Complete the I/O from iocb->kiocb.ki_complete()
 *
 * Note that this function can be called from a bottom half context,
 * hence we need to queue the fput() etc to a workqueue
 */
static void
nfs_local_pgio_complete(struct nfs_local_kiocb *iocb)
{
	queue_work(nfsiod_workqueue, &iocb->work);
}

static void
nfs_local_read_done(struct nfs_local_kiocb *iocb, long status)
{
	struct nfs_pgio_header *hdr = iocb->hdr;
	struct file *filp = iocb->kiocb.ki_filp;

	nfs_local_pgio_done(hdr, status);

	if (hdr->res.count != hdr->args.count ||
	    hdr->args.offset + hdr->res.count >= i_size_read(file_inode(filp)))
		hdr->res.eof = true;

	dprintk("%s: read %ld bytes eof %d.\n", __func__,
			status > 0 ? status : 0, hdr->res.eof);
}

static void
nfs_local_read_aio_complete(struct kiocb *kiocb, long ret, long ret2)
{
	struct nfs_local_kiocb *iocb = container_of(kiocb,
			struct nfs_local_kiocb, kiocb);

	nfs_local_read_done(iocb, ret);
	nfs_local_pgio_complete(iocb);
}

static int
nfs_do_local_read(struct nfs_pgio_header *hdr, struct file *filp,
		const struct rpc_call_ops *call_ops)
{
	struct nfs_local_kiocb *iocb;
	struct iov_iter iter;
	ssize_t status;

	dprintk("%s: vfs_read count=%u pos=%llu\n",
		__func__, hdr->args.count, hdr->args.offset);

	iocb = nfs_local_iocb_alloc(hdr, filp, GFP_KERNEL);
	if (iocb == NULL)
		return -ENOMEM;
	nfs_local_iter_init(&iter, iocb, READ);

	nfs_local_pgio_init(hdr, call_ops);
	hdr->res.eof = false;

	if (iocb->kiocb.ki_flags & IOCB_DIRECT) {
		INIT_WORK(&iocb->work, nfs_local_pgio_complete_work);
		iocb->kiocb.ki_complete = nfs_local_read_aio_complete;
	}

	status = call_read_iter(filp, &iocb->kiocb, &iter);
	if (status != -EIOCBQUEUED) {
		nfs_local_read_done(iocb, status);
		nfs_local_iocb_free(iocb);
	}
	return status;
}

static void
nfs_set_local_verifier(struct nfs_writeverf *verf, enum nfs3_stable_how how)
{
	memset(verf->verifier.data, 0xaa, sizeof(verf->verifier.data));
	verf->committed = how;
}

static enum nfs3_stable_how
nfs_iocb_to_stable_how(struct kiocb *kiocb)
{
	switch (kiocb->ki_flags & (IOCB_DSYNC|IOCB_SYNC)) {
	default:
		break;
	case IOCB_DSYNC:
		return NFS_DATA_SYNC;
	case IOCB_DSYNC|IOCB_SYNC:
		return NFS_FILE_SYNC;
	}
	return NFS_UNSTABLE;
}

static void
nfs_get_vfs_attr(struct file *filp, struct nfs_fattr *fattr)
{
	struct kstat stat;

	if (fattr != NULL && vfs_getattr(&filp->f_path, &stat,
					 STATX_ATIME | STATX_MTIME | STATX_CTIME | STATX_SIZE,
					 AT_STATX_SYNC_AS_STAT) == 0) {
		fattr->valid = NFS_ATTR_FATTR_CHANGE | NFS_ATTR_FATTR_SIZE |
			NFS_ATTR_FATTR_ATIME | NFS_ATTR_FATTR_MTIME |
			NFS_ATTR_FATTR_CTIME;
		fattr->size = stat.size;
		fattr->atime.tv_sec = stat.atime.tv_sec;
		fattr->atime.tv_nsec = stat.atime.tv_nsec;
		fattr->mtime.tv_sec = stat.mtime.tv_sec;
		fattr->mtime.tv_nsec = stat.mtime.tv_nsec;
		fattr->ctime.tv_sec = stat.ctime.tv_sec;
		fattr->ctime.tv_nsec = stat.ctime.tv_nsec;
		fattr->change_attr = nfs_timespec_to_change_attr(&fattr->ctime);
	}
}

static void
nfs_local_write_done(struct nfs_local_kiocb *iocb, long status)
{
	struct nfs_pgio_header *hdr = iocb->hdr;

	dprintk("%s: wrote %ld bytes.\n", __func__, status > 0 ? status : 0);

	nfs_local_pgio_done(hdr, status);

	nfs_set_local_verifier(hdr->res.verf,
			nfs_iocb_to_stable_how(&iocb->kiocb));
}

static void
nfs_local_write_aio_complete_work(struct work_struct *work)
{
	struct nfs_local_kiocb *iocb = container_of(work,
			struct nfs_local_kiocb, work);

	nfs_get_vfs_attr(iocb->kiocb.ki_filp, iocb->hdr->res.fattr);
	nfs_local_pgio_complete_work(work);
}

static void
nfs_local_write_aio_complete(struct kiocb *kiocb, long ret, long ret2)
{
	struct nfs_local_kiocb *iocb = container_of(kiocb,
			struct nfs_local_kiocb, kiocb);

	nfs_local_write_done(iocb, ret);
	nfs_local_pgio_complete(iocb);
}

static int
nfs_do_local_write(struct nfs_pgio_header *hdr, struct file *filp,
		const struct rpc_call_ops *call_ops)
{
	struct nfs_local_kiocb *iocb;
	struct iov_iter iter;
	ssize_t status;

	dprintk("%s: vfs_write count=%u pos=%llu %s\n",
		__func__, hdr->args.count, hdr->args.offset,
		(hdr->args.stable == NFS_UNSTABLE) ?  "unstable" : "stable");

	iocb = nfs_local_iocb_alloc(hdr, filp, GFP_NOIO);
	if (iocb == NULL)
		return -ENOMEM;
	nfs_local_iter_init(&iter, iocb, WRITE);

	switch (hdr->args.stable) {
	default:
		break;
	case NFS_DATA_SYNC:
		iocb->kiocb.ki_flags |= IOCB_DSYNC;
		break;
	case NFS_FILE_SYNC:
		iocb->kiocb.ki_flags |= IOCB_DSYNC|IOCB_SYNC;
	}
	nfs_local_pgio_init(hdr, call_ops);

	if (iocb->kiocb.ki_flags & IOCB_DIRECT) {
		INIT_WORK(&iocb->work, nfs_local_write_aio_complete_work);
		iocb->kiocb.ki_complete = nfs_local_write_aio_complete;
	}

	file_start_write(filp);
	status = call_write_iter(filp, &iocb->kiocb, &iter);
	file_end_write(filp);
	if (status != -EIOCBQUEUED) {
		nfs_local_write_done(iocb, status);
		nfs_get_vfs_attr(filp, hdr->res.fattr);
		nfs_local_iocb_free(iocb);
	}
	return status;
}

static struct file *
nfs_local_file_open_cached(struct nfs_client *clp, const struct cred *cred,
			   struct nfs_fh *fh, struct nfs_open_context *ctx)
{
	struct file *filp = ctx->local_filp;

	if (!filp) {
		struct file *new = nfs_local_open_fh(clp, cred, fh, ctx->mode);
		if (IS_ERR_OR_NULL(new))
			return new;
		/* try to put this one in the slot */
		filp = cmpxchg(&ctx->local_filp, NULL, new);
		if (filp != NULL)
			fput(new);
		else
			filp = new;
	}
	return get_file(filp);
}

struct file *
nfs_local_file_open(struct nfs_client *clp, const struct cred *cred,
		    struct nfs_fh *fh, struct nfs_open_context *ctx)
{
	if (!nfs_server_is_local(clp))
		return NULL;
	return nfs_local_file_open_cached(clp, cred, fh, ctx);
}

int
nfs_local_doio(struct nfs_client *clp, struct file *filp,
	       struct nfs_pgio_header *hdr,
	       const struct rpc_call_ops *call_ops)
{
	int status = 0;

	if (!hdr->args.count)
		goto out_fput;
	/* Don't support filesystems without read_iter/write_iter */
	if (!filp->f_op->read_iter || !filp->f_op->write_iter) {
		nfs_local_disable(clp);
		status = -EAGAIN;
		goto out_fput;
	}

	switch (hdr->rw_mode) {
	case FMODE_READ:
		status = nfs_do_local_read(hdr, filp, call_ops);
		break;
	case FMODE_WRITE:
		status = nfs_do_local_write(hdr, filp, call_ops);
		break;
	default:
		dprintk("%s: invalid mode: %d\n", __func__,
			hdr->rw_mode);
		status = -EINVAL;
	}
out_fput:
	if (status != -EIOCBQUEUED)
		fput(filp);

	return status;
}
EXPORT_SYMBOL_GPL(nfs_local_doio);

int
nfs_local_commit(struct nfs_client *clp, struct file *filp,
		 struct nfs_commit_data *data)
{
	loff_t end;
	int status;

	dprintk("%s: commit %llu - %u\n", __func__,
		data->args.offset, data->args.count);

	end = data->args.count ? data->args.offset + data->args.count : -1;
	status = vfs_fsync_range(filp, data->args.offset, end, localio_datasync);
	fput(filp);
	if (status >= 0) {
		nfs_set_local_verifier(data->res.verf, NFS_FILE_SYNC);
		data->res.op_status = NFS4_OK;
		data->task.tk_status = 0;
	} else {
		data->res.op_status = nfs4errno(status);
		data->task.tk_status = status;
	}

	return status;
}
EXPORT_SYMBOL_GPL(nfs_local_commit);

static int
nfs_client_add_addr(struct nfs_client *clnt, char *buf, gfp_t flags)
{
	struct nfs_local_addr *addr;
	struct sockaddr *sap;

	dprintk("%s: adding new local IP %s\n", __func__, buf);
	addr = kmalloc(sizeof(*addr), flags);
	if (!addr) {
		printk(KERN_WARNING "NFS: cannot alloc new addr\n");
		return -ENOMEM;
	}
	sap = (struct sockaddr *)&addr->address;
	addr->addrlen = rpc_pton(clnt->cl_net, buf, strlen(buf),
				sap, sizeof(addr->address));
	if (!addr->addrlen) {
		printk(KERN_WARNING "NFS: cannot parse new addr %s\n",
				buf);
		kfree(addr);
		return -EINVAL;
	}
	list_add(&addr->cl_addrs, &clnt->cl_local_addrs);

	return 0;
}

static int
nfs_client_add_v4_addr(struct nfs_client *clnt, struct in_device *indev,
		       char *buf, size_t buflen)
{
	int ret;

	for_ifa(indev) {
		snprintf(buf, buflen, "%pI4", &ifa->ifa_local);
		ret = nfs_client_add_addr(clnt, buf, GFP_KERNEL);
		if (ret < 0)
			return ret;
	} endfor_ifa(indev);

	return 0;
}

#if IS_ENABLED(CONFIG_IPV6)
static int
nfs_client_add_v6_addr(struct nfs_client *clnt, struct inet6_dev *in6dev,
		       char *buf, size_t buflen)
{
	struct inet6_ifaddr *ifp;
	int ret = 0;

	read_lock_bh(&in6dev->lock);
	list_for_each_entry(ifp, &in6dev->addr_list, if_list) {
		rpc_ntop6_addr_noscopeid(&ifp->addr, buf, buflen);
		ret = nfs_client_add_addr(clnt, buf, GFP_ATOMIC);
		if (ret < 0)
			goto out;
	}
out:
	read_unlock_bh(&in6dev->lock);
	return ret;
}
#else /* CONFIG_IPV6 */
static int
nfs_client_add_v6_addr(struct nfs_client *clnt, struct inet6_dev *in6dev,
		       char *buf, size_t buflen)
{
	return 0;
}
#endif

/* Find out all local IP addresses. Ignore errors
 * because local IO can be optional.
 */
void
nfs_probe_local_addr(struct nfs_client *clnt)
{
	struct net_device *dev;
	struct in_device *indev;
	struct inet6_dev *in6dev;
	char buf[INET6_ADDRSTRLEN + IPV6_SCOPE_ID_LEN];
	size_t buflen = sizeof(buf);

	rtnl_lock();

	for_each_netdev(clnt->cl_net, dev) {
		if (dev->type == ARPHRD_LOOPBACK ||
		    !(dev->flags & IFF_UP))
			continue;
		indev = __in_dev_get_rtnl(dev);
		if (indev &&
		    nfs_client_add_v4_addr(clnt, indev, buf, buflen) < 0)
			break;
		in6dev = __in6_dev_get(dev);
		if (in6dev &&
		    nfs_client_add_v6_addr(clnt, in6dev, buf, buflen) < 0)
			break;
	}

	rtnl_unlock();
}
