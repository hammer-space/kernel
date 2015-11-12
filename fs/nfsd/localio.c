/*
 * NFS server support for local clients to bypass network stack
 *
 * Copyright (C) 2014 Weston Andros Adamson <dros@primarydata.com>
 */

#include <linux/exportfs.h>
#include <linux/sunrpc/svcauth_gss.h>
#include <linux/sunrpc/clnt.h>
#include <linux/nfs.h>
#include <linux/string.h>

#include "nfsd.h"
#include "vfs.h"
#include "netns.h"

#define NFSDDBG_FACILITY		NFSDDBG_FH

static void
nfsd_local_fakerqst_destroy(struct svc_rqst *rqstp)
{
	if (rqstp->rq_cred.cr_group_info)
		put_group_info(rqstp->rq_cred.cr_group_info);
	kfree(rqstp->rq_cred.cr_principal);
	kfree(rqstp->rq_xprt);
	kfree(rqstp);
}

static struct svc_rqst *
nfsd_local_fakerqst_create(struct rpc_clnt *rpc_clnt, const struct cred *cred)
{
	struct svc_rqst *rqstp;
	struct sockaddr_in6 *sin6;
	/* XXX use current->nsproxy->net_ns instead? */
	struct net *net = rpc_net_ns(rpc_clnt);
	struct nfsd_net *nn = net_generic(net, nfsd_net_id);
	int status;

	rqstp = kzalloc(sizeof(*rqstp), GFP_KERNEL);
	if (!rqstp) {
		status = -ENOMEM;
		goto out_err;
	}

	rqstp->rq_xprt = kzalloc(sizeof(*rqstp->rq_xprt), GFP_KERNEL);
	if (!rqstp->rq_xprt) {
		status = -ENOMEM;
		goto out_err;
	}

	rqstp->rq_xprt->xpt_net = net;
	set_bit(RQ_SECURE, &rqstp->rq_flags);
	rqstp->rq_proc = 1;	/* XXX just can't be zero! */
	rqstp->rq_server = nn->nfsd_serv;
	rqstp->rq_addr.ss_family = AF_INET6;
	sin6 = (struct sockaddr_in6 *)&rqstp->rq_addr;
	memcpy(&sin6->sin6_addr, &in6addr_loopback, sizeof(struct in6_addr));

	if (!rpcauth_map_to_svc_cred(rpc_clnt->cl_auth, cred,
				     &rqstp->rq_cred)) {
		dprintk("%s :map cred failed\n", __func__);
		status = -EINVAL;
		goto out_err;
	}

	/* set up enough for svcauth_unix_set_client to be able to wait
	 * for the cache downcall */
	INIT_LIST_HEAD(&rqstp->rq_xprt->xpt_deferred);
	kref_init(&rqstp->rq_xprt->xpt_ref);
	set_bit(RQ_USEDEFERRAL, &rqstp->rq_flags);
	rqstp->rq_chandle.defer = svc_defer;
	rqstp->rq_chandle.thread_wait = 1;

	status = svcauth_unix_set_client(rqstp);
	if (status != SVC_OK) {
		status = -ETIMEDOUT;
		goto out_err;
	}

	return rqstp;

out_err:
	if (rqstp && !IS_ERR(rqstp))
		nfsd_local_fakerqst_destroy(rqstp);
	return ERR_PTR(status);
}

/*
 * nfsd_lookup_local_fh - lookup a local filehandle @nfs_fh and map to @path
 *
 * This function maps a local fh to a path on a local filesystem.
 * This is useful when the nfs client has the local server mounted - it can
 * avoid all the NFS overhead with reads, writes and commits.
 *
 * on successful return, caller is responsibe for calling path_put
 */
int nfsd_lookup_local_fh(struct rpc_clnt *rpc_clnt,
			 const struct cred *cred,
			 const struct nfs_fh *nfs_fh,
			 const fmode_t fmode,
			 struct path *path)
{
	struct svc_rqst *rqstp;
	struct svc_fh fh;
	int status = 0;
	int mayflags = 0;
	__be32 beres;

	rqstp = nfsd_local_fakerqst_create(rpc_clnt, cred);
	if (IS_ERR(rqstp)) {
		status = PTR_ERR(rqstp);
		goto out;
	}

	/* nfs_fh -> svc_fh */
	if (nfs_fh->size > NFS4_FHSIZE) {
		status = -EINVAL;
		goto out;
	}
	fh.fh_handle.fh_size = nfs_fh->size;
	memcpy(fh.fh_handle.fh_base.fh_pad, nfs_fh->data, nfs_fh->size);
	fh.fh_dentry = NULL;
	fh.fh_export = NULL;

	if (fmode & FMODE_READ)
		mayflags |= NFSD_MAY_READ;
	if (fmode & FMODE_WRITE)
		mayflags |= NFSD_MAY_WRITE;

	beres = fh_verify(rqstp, &fh, 0, mayflags);
	if (beres) {
		status = nfs_stat_to_errno(be32_to_cpu(beres));
		dprintk("%s: fh_verify failed %d\n", __func__, status);
		goto out;
	}

	path->mnt = fh.fh_export->ex_path.mnt;
	path->dentry = fh.fh_dentry;

out:
	if (rqstp && !IS_ERR(rqstp))
		nfsd_local_fakerqst_destroy(rqstp);
	return status;
}
EXPORT_SYMBOL_GPL(nfsd_lookup_local_fh);

/* Compile time type checking, not used by anything */
nfs_to_nfsd_lookup_t nfsd_lookup_local_fh_typecheck = nfsd_lookup_local_fh;
