/*
 * linux/net/sunrpc/auth_name/auth_name.c
 *
 * SEC NAME client authentication.
 *
 *  Copyright (c) 2017 Primary Data.
 *  All rights reserved.
 *
 *  Weston Andros Adamson <dros@monkey.org>
 *
 * Based on auth_gss.c:
 *
 *  Copyright (c) 2000 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Dug Song       <dugsong@monkey.org>
 *  Andy Adamson   <andros@umich.edu>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions
 *  are met:
 *
 *  1. Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *  2. Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 *  3. Neither the name of the University nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 *  DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 *  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 *  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 *  BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <linux/module.h>
#include <linux/init.h>
#include <linux/types.h>
#include <linux/slab.h>
#include <linux/sched.h>
#include <linux/pagemap.h>
#include <linux/sunrpc/clnt.h>
#include <linux/sunrpc/auth.h>
#include <linux/sunrpc/auth_name.h>
#include <linux/workqueue.h>
#include <asm/uaccess.h>
#include <linux/hashtable.h>
#include <linux/nfs4idmap.h>


/*
 * type (size 4), len (size 4), version (size 4), proc (size 4),
 * verf (size 8), sessionid (size 4)
 */
#define AUTH_NAME_CRED_SZ XDR_QUADLEN(4 + 4 + 4 + 4 + 8 + 4)

/* type (size 4) and size - always 0 (size 4) */
#define AUTH_NAME_VERF_SZ XDR_QUADLEN(4 + 4)

static const struct rpc_authops authname_ops;

static const struct rpc_credops name_credops;
static const struct rpc_credops name_destroyops;

#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)
# define RPCDBG_FACILITY	RPCDBG_AUTH
#endif

static DEFINE_HASHTABLE(name_auth_hash_table, 4);
static DEFINE_SPINLOCK(name_auth_hash_lock);

struct name_auth {
	struct kref kref;
	struct hlist_node hash;
	struct rpc_auth rpc_auth;
	struct rpc_clnt *client;
	struct net *net;
	const char *target_name;
};

struct auth_name_payload_ctx {
	struct page		**pages;
	size_t			len;
	struct name_cred	*name_cred;
	struct name_session	*name_session;
	u64			verf;
	u32			status;
	u32			session_id;
};

static void name_put_auth(struct name_auth *name_auth);

static struct name_session *
name_session_alloc(void)
{
	struct name_session *name_session;

	name_session = kzalloc(sizeof(*name_session), GFP_NOFS);
	if (name_session != NULL) {
		name_session->ns_proc = AUTH_NAME_PROC_INIT;
		atomic_set(&name_session->ns_count, 1);
	}
	return name_session;
}

static inline struct name_session *
name_session_get(struct name_session *name_session)
{
	if (name_session) {
		dprintk("RPC: %s refcount %p (pre) %d\n", __func__,
			name_session, atomic_read(&name_session->ns_count));
		if (!atomic_inc_not_zero(&name_session->ns_count))
			return NULL;
	}

	return name_session;
}

static void
name_session_free_rcu(struct rcu_head *head)
{
	struct name_session *name_session = container_of(head,
						struct name_session, ns_rcu);
	kfree(name_session);
}

static void
name_session_free(struct name_session *name_session)
{
	dprintk("RPC: %s session %p\n", __func__, name_session);
	call_rcu(&name_session->ns_rcu, name_session_free_rcu);
}

static inline void
name_session_put(struct name_session *name_session)
{
	if (!name_session)
		return;
	dprintk("RPC: %s refcount %p (pre) %d\n", __func__, name_session,
		atomic_read(&name_session->ns_count));
	if (atomic_dec_and_test(&name_session->ns_count))
		name_session_free(name_session);
}

static struct name_session *
name_cred_get_session(struct rpc_cred *cred)
{
	struct name_cred *name_cred = container_of(cred, struct name_cred,
							nc_base);
	struct name_session *name_session = NULL;

	rcu_read_lock();
	name_session = rcu_dereference(name_cred->nc_session);
	name_session = name_session_get(name_session);
	rcu_read_unlock();
	return name_session;
}

static void
name_cred_set_session(struct rpc_cred *cred, struct name_session *name_session)
{
	struct name_cred *name_cred = container_of(cred, struct name_cred,
							nc_base);
	struct name_session *old_session;

	name_session = name_session_get(name_session);
	old_session = name_cred_get_session(cred);

	dprintk("RPC: %s old session %p, new session %p\n", __func__,
		old_session, name_session);

	rcu_assign_pointer(name_cred->nc_session, name_session);

	/*
	 * two puts of old_session - one for the name_cred_get_session, one
	 * for the above name_session_get when it was the *new* session being
	 * set
	 */
	name_session_put(old_session);
	name_session_put(old_session);

	if (name_session) {
		set_bit(RPCAUTH_CRED_UPTODATE, &cred->cr_flags);
		smp_mb__after_atomic();
	}
}

static int
name_cred_completion_alloc(struct name_cred *name_cred)
{
	struct rpc_completion *rc;

	if (rcu_access_pointer(name_cred->nc_init_completion))
		return 0;
	rc = rpc_completion_alloc(GFP_NOFS);
	if (!rc)
		return -ENOMEM;
	rcu_read_lock();
	if (cmpxchg(&name_cred->nc_init_completion, NULL, rc)) {
		rcu_read_unlock();
		rpc_completion_free_rcu(rc);
	} else
		rcu_read_unlock();
	return 0;
}

static void
name_cred_completion_free(struct name_cred *name_cred)
{
	struct rpc_completion *rc;

	rc = xchg(&name_cred->nc_init_completion, NULL);
	if (rc)
		rpc_completion_free_rcu(rc);
}

static bool
name_cred_completion_wait(struct name_cred *name_cred, struct rpc_task *task)
{
	struct rpc_completion *rc;
	bool ret = false;

	rcu_read_lock();
	rc = rcu_dereference(name_cred->nc_init_completion);
	if (rc)
		ret = rpc_completion_wait(rc, task);
	rcu_read_unlock();
	return ret;
}

static void
name_cred_completion_done(struct name_cred *name_cred)
{
	struct rpc_completion *rc;

	rcu_read_lock();
	rc = rcu_dereference(name_cred->nc_init_completion);
	if (rc) {
		rpc_completion_complete(rc);
		name_cred_completion_free(name_cred);
	}
	rcu_read_unlock();
}

static void
name_cred_init_complete(struct name_cred *name_cred)
{
	struct rpc_cred *cred = &name_cred->nc_base;

	clear_bit(RPCAUTH_CRED_INIT, &cred->cr_flags);
	smp_mb__after_atomic();
	name_cred_completion_done(name_cred);
}

static int
xdr_stream_encode_string(struct xdr_stream *xdr, const char *str)
{
	size_t len = strlen(str);
	__be32 *p = xdr_reserve_space(xdr, 4 + len);

	if (unlikely(!p))
		return -EMSGSIZE;
	xdr_encode_opaque(p, str, len);
	return 0;
}

/*
 * NULL ping with data
 */
static int
auth_name_encode_init_args(struct name_cred *name_cred, struct page **pages, unsigned int len)
{
	struct xdr_stream xdr = { 0 };
	struct xdr_buf buf = { { { NULL, }, }, };
	int i;

	// AUTH_NAME_MAX_XDRLEN
	xdr_init_encode_pages(&xdr, &buf, pages, len);
	buf.flags |= XDRBUF_SPARSE_PAGES;

	/* user principal */
	dprintk("RPC: user principal: %s\n", name_cred->nc_user_principal);
	xdr_stream_encode_string(&xdr, name_cred->nc_user_principal);

	/* group principal */
	dprintk("RPC: group principal: %s\n", name_cred->nc_group_principal);
	xdr_stream_encode_string(&xdr, name_cred->nc_group_principal);

	xdr_stream_encode_u32(&xdr, name_cred->nc_other_principals_count);
	for (i = 0; i < name_cred->nc_other_principals_count; i++) {
		const char *other = name_cred->nc_other_principals[i];
		if (xdr_stream_encode_string(&xdr, other))
			break;
		dprintk("RPC: extra principal: %s\n", other);
	}

	xdr_commit_encode(&xdr);

	return buf.len;
}

static void
rpcproc_encode_null_payload_init_call(struct rpc_rqst *rqstp,
				      struct xdr_stream *xdr, const void *obj)
{
	const struct auth_name_payload_ctx *ctx = obj;

	xdr_write_pages(xdr, ctx->pages, 0, ctx->len);
}

static int
rpcproc_decode_null_payload_init_reply(struct rpc_rqst *rqstp,
				       struct xdr_stream *xdr, void *obj)
{
	struct auth_name_payload_ctx *ctx = obj;

	if (xdr_stream_decode_u32(xdr, &ctx->status))
		return -EIO;

	if (xdr_stream_decode_u64(xdr, &ctx->verf))
		return -EIO;

	if (xdr_stream_decode_u32(xdr, &ctx->session_id))
		return -EIO;

	return 0;
}

static void
rpc_ping_payload_done(struct rpc_task *task, void *obj)
{
	struct auth_name_payload_ctx *ctx = obj;
	struct rpc_cred *cred = &ctx->name_cred->nc_base;

	if (!task->tk_status && !ctx->status) {
		ctx->name_session->ns_proc = AUTH_NAME_PROC_REFERENCE;
		ctx->name_session->ns_session_id = ctx->session_id;
		ctx->name_session->ns_verf = ctx->verf;

		name_cred_set_session(cred, ctx->name_session);
		clear_bit(RPCAUTH_CRED_NEW, &cred->cr_flags);
		dprintk("RPC: %s got res %u session_id %u on session init!",
				__func__, ctx->status, ctx->session_id);
	} else
		dprintk("RPC: %s got status %d, res %u on session init!",
				__func__, task->tk_status, ctx->status);
}

static void
rpc_ping_payload_release(void *obj)
{
	const size_t npages = DIV_ROUND_UP(AUTH_NAME_MAX_XDRLEN, PAGE_SIZE) + 1;
	struct auth_name_payload_ctx *ctx = obj;
	struct page **pages = ctx->pages;
	unsigned int i;

	for (i = 0; i < npages && pages[i]; i++)
		put_page(pages[i]);
	kfree(ctx->pages);
	name_session_put(ctx->name_session);
	name_cred_init_complete(ctx->name_cred);
	put_rpccred(&ctx->name_cred->nc_base);
	kfree(ctx);
}

static struct rpc_procinfo rpcproc_null_payload = {
	.p_encode = rpcproc_encode_null_payload_init_call,
	.p_decode = rpcproc_decode_null_payload_init_reply,
	.p_arglen = 100,
	.p_replen = 100,
	.p_timer = 0,
	.p_statidx = 0,
	.p_name = "NULL (AUTH_NAME init)",
};

static const struct rpc_call_ops rpc_ping_ops = {
	.rpc_call_done = rpc_ping_payload_done,
	.rpc_release = rpc_ping_payload_release,
};

static int rpc_ping_payload_init(struct rpc_clnt *clnt, struct rpc_cred *cred)
{
	const size_t npages = DIV_ROUND_UP(AUTH_NAME_MAX_XDRLEN, PAGE_SIZE) + 1;
	struct name_cred *name_cred = container_of(cred, struct name_cred,
							nc_base);
	struct auth_name_payload_ctx *ctx = kmalloc(sizeof(*ctx), GFP_NOFS);
	struct rpc_message msg = {
		.rpc_proc = &rpcproc_null_payload,
		.rpc_argp = ctx,
		.rpc_resp = ctx,
	};
	struct rpc_task_setup task_setup_data = {
		.rpc_client = clnt,
		.rpc_message = &msg,
		.rpc_op_cred = cred,
		.callback_ops = &rpc_ping_ops,
		.callback_data = ctx,
		.flags = RPC_TASK_SOFT | RPC_TASK_SOFTCONN | RPC_TASK_ASYNC,
	};
	struct rpc_task *task;

	if (!ctx)
		goto out_enomem;
	ctx->status = 0;
	ctx->name_cred = name_cred;
	ctx->name_session = name_session_alloc();
	if (!ctx->name_session)
		goto out_enomem;
	ctx->pages = kcalloc(npages, sizeof(*ctx->pages), GFP_NOFS);
	if (!ctx->pages)
		goto out_session_put;
	ctx->len = auth_name_encode_init_args(name_cred, ctx->pages,
			AUTH_NAME_MAX_XDRLEN);
	get_rpccred(cred);
	task = rpc_run_task(&task_setup_data);
	if (IS_ERR(task))
		return PTR_ERR(task);
	rpc_put_task(task);
	return -EAGAIN;
out_session_put:
	name_session_put(ctx->name_session);
out_enomem:
	name_cred_init_complete(ctx->name_cred);
	kfree(ctx);
	return -ENOMEM;
}

static struct name_auth *
name_create_new(const struct rpc_auth_create_args *args, struct rpc_clnt *clnt)
{
	struct name_auth *name_auth;
	struct rpc_auth *auth;
	int err = -ENOMEM;

	dprintk("RPC:       creating NAME authenticator for client %p\n", clnt);

	if (!try_module_get(THIS_MODULE))
		return ERR_PTR(err);
	if (!(name_auth = kmalloc(sizeof(*name_auth), GFP_NOFS)))
		goto out_dec;
	INIT_HLIST_NODE(&name_auth->hash);
	name_auth->target_name = NULL;
	if (args->target_name) {
		name_auth->target_name = kstrdup(args->target_name, GFP_NOFS);
		if (name_auth->target_name == NULL)
			goto err_free;
	}
	name_auth->client = clnt;
	name_auth->net = get_net(rpc_net_ns(clnt));
	err = -EINVAL;
	auth = &name_auth->rpc_auth;
	auth->au_cslack = AUTH_NAME_CRED_SZ + AUTH_NAME_VERF_SZ;
	auth->au_rslack = AUTH_NAME_VERF_SZ;
	auth->au_verfsize = AUTH_NAME_VERF_SZ;
	auth->au_ralign = AUTH_NAME_VERF_SZ;
	auth->au_flags = 0;
	auth->au_ops = &authname_ops;
	auth->au_flavor = RPC_AUTH_NAME;
	auth->au_credcache = NULL;
	refcount_set(&auth->au_count, 1);
	kref_init(&name_auth->kref);

	err = rpcauth_init_credcache(auth);
	if (err)
		goto err_free;
	return name_auth;
err_free:
	kfree(name_auth->target_name);
	kfree(name_auth);
out_dec:
	module_put(THIS_MODULE);
	return ERR_PTR(err);
}

static void
name_free(struct name_auth *name_auth)
{
	put_net(name_auth->net);
	kfree(name_auth->target_name);

	kfree(name_auth);
	module_put(THIS_MODULE);
}

static void
name_free_callback(struct kref *kref)
{
	struct name_auth *name_auth = container_of(kref, struct name_auth, kref);

	name_free(name_auth);
}

static void
name_put_auth(struct name_auth *name_auth)
{
	kref_put(&name_auth->kref, name_free_callback);
}

static void
name_destroy(struct rpc_auth *auth)
{
	struct name_auth *name_auth = container_of(auth,
			struct name_auth, rpc_auth);

	dprintk("RPC:       destroying NAME authenticator %p flavor %d\n",
			auth, auth->au_flavor);

	/* FIXME: hash_hashed outside of spinlock! */
	if (hash_hashed(&name_auth->hash)) {
		spin_lock(&name_auth_hash_lock);
		hash_del(&name_auth->hash);
		spin_unlock(&name_auth_hash_lock);
	}

	rpcauth_destroy_credcache(auth);

	name_put_auth(name_auth);
}

/*
 * Auths may be shared between rpc clients that were cloned from a
 * common client with the same xprt, if they also share the flavor and
 * target_name.
 *
 * The auth is looked up from the oldest parent sharing the same
 * cl_xprt, and the auth itself references only that common parent
 * (which is guaranteed to last as long as any of its descendants).
 */
static struct name_auth *
name_auth_find_or_add_hashed(const struct rpc_auth_create_args *args,
		struct rpc_clnt *clnt,
		struct name_auth *new)
{
	struct name_auth *name_auth;
	unsigned long hashval = (unsigned long)clnt;

	/* FIXME: global lock is bad! */
	spin_lock(&name_auth_hash_lock);
	hash_for_each_possible(name_auth_hash_table,
			name_auth,
			hash,
			hashval) {
		if (name_auth->client != clnt)
			continue;
		if (name_auth->rpc_auth.au_flavor != args->pseudoflavor)
			continue;
		if (name_auth->target_name != args->target_name) {
			if (name_auth->target_name == NULL)
				continue;
			if (args->target_name == NULL)
				continue;
			if (strcmp(name_auth->target_name, args->target_name))
				continue;
		}
		if (!refcount_inc_not_zero(&name_auth->rpc_auth.au_count))
			continue;
		goto out;
	}
	if (new)
		hash_add(name_auth_hash_table, &new->hash, hashval);
	name_auth = new;
out:
	spin_unlock(&name_auth_hash_lock);
	return name_auth;
}

static struct name_auth *
name_create_hashed(const struct rpc_auth_create_args *args, struct rpc_clnt *clnt)
{
	struct name_auth *name_auth;
	struct name_auth *new;

	name_auth = name_auth_find_or_add_hashed(args, clnt, NULL);
	if (name_auth != NULL)
		goto out;
	new = name_create_new(args, clnt);
	if (IS_ERR(new))
		return new;
	name_auth = name_auth_find_or_add_hashed(args, clnt, new);
	if (name_auth != new)
		name_destroy(&new->rpc_auth);
out:
	return name_auth;
}

static struct rpc_auth *
name_create(const struct rpc_auth_create_args *args, struct rpc_clnt *clnt)
{
	struct name_auth *name_auth;
	struct rpc_xprt_switch *xps = rcu_access_pointer(clnt->cl_xpi.xpi_xpswitch);

	while (clnt != clnt->cl_parent) {
		struct rpc_clnt *parent = clnt->cl_parent;
		/* Find the original parent for this transport */
		if (rcu_access_pointer(parent->cl_xpi.xpi_xpswitch) != xps)
			break;
		clnt = parent;
	}

	name_auth = name_create_hashed(args, clnt);
	if (IS_ERR(name_auth))
		return ERR_CAST(name_auth);
	return &name_auth->rpc_auth;
}

static int
name_destroying_context(struct rpc_cred *cred)
{
	struct name_auth *name_auth = container_of(cred->cr_auth, struct name_auth, rpc_auth);
	struct rpc_task *task;

	if (test_bit(RPCAUTH_CRED_UPTODATE, &cred->cr_flags) == 0)
		return 0;

	cred->cr_ops = &name_destroyops;

	task = rpc_call_null(name_auth->client, cred, RPC_TASK_ASYNC|RPC_TASK_SOFT);
	if (!IS_ERR(task))
		rpc_put_task(task);

	return 1;
}

static void
name_free_cred(struct name_cred *name_cred)
{
	struct name_session *name_session;
	size_t i;

	dprintk("RPC:       %s cred=%p\n", __func__, name_cred);

	rcu_read_lock();
	name_session = rcu_dereference(name_cred->nc_session);
	name_session_put(name_session);
	rcu_read_unlock();

	/* free mapping cache */
	kfree(name_cred->nc_user_principal);
	kfree(name_cred->nc_group_principal);
	for (i = 0; i < name_cred->nc_other_principals_count; i++)
		kfree(name_cred->nc_other_principals[i]);
	kfree(name_cred->nc_other_principals);

	put_cred(name_cred->nc_base.cr_cred);

	kfree(name_cred);
}

static void
name_free_cred_callback(struct rcu_head *head)
{
	struct name_cred *name_cred = container_of(head, struct name_cred, nc_base.cr_rcu);
	name_free_cred(name_cred);
}

static void
name_destroy_nullcred(struct rpc_cred *cred)
{
	struct name_cred *name_cred = container_of(cred, struct name_cred, nc_base);
	struct name_auth *name_auth = container_of(cred->cr_auth, struct name_auth, rpc_auth);

	name_cred_completion_done(name_cred);
	call_rcu(&cred->cr_rcu, name_free_cred_callback);
	name_put_auth(name_auth);
}

static void
name_destroy_cred(struct rpc_cred *cred)
{

	if (name_destroying_context(cred))
		return;
	name_destroy_nullcred(cred);
}

static int
name_hash_cred(struct auth_cred *acred, unsigned int hashbits)
{
	return hash_64(from_kgid(&init_user_ns, acred->cred->fsgid) |
		((u64)from_kuid(&init_user_ns, acred->cred->fsuid) <<
			(sizeof(gid_t) * 8)), hashbits);
}

static struct rpc_cred *
name_lookup_cred(struct rpc_auth *auth, struct auth_cred *acred, int flags)
{
	return rpcauth_lookup_credcache(auth, acred, flags, GFP_NOFS);
}

static int
name_map_uid(struct rpc_task *task, kuid_t uid, char **namep)
{
	char buf[AUTH_NAME_MAX_PRINCIPAL_LEN] = { 0, };
	char *name;
	int ret;

	dprintk("RPC: %s map uid\n", __func__);
	ret = sunrpc_map_uid_to_name(task->tk_client, uid, buf, sizeof(buf),
				     false);
	if (ret < 0) {
		dprintk("RPC: %s map uid FAIL %d\n", __func__, ret);
		return ret;
	}

	dprintk("RPC: %s map uid to %s\n", __func__, buf);

	name = kstrdup(buf, GFP_NOFS);
	if (!name)
		return -ENOMEM;

	*namep = name;
	return 0;
}

static int
name_map_gid(struct rpc_task *task, kgid_t gid, char **groupp)
{
	char buf[AUTH_NAME_MAX_PRINCIPAL_LEN] = { 0, };
	char *group;
	int ret;

	dprintk("RPC: %s map gid\n", __func__);
	ret = sunrpc_map_gid_to_group(task->tk_client, gid, buf, sizeof(buf),
				      false);
	if (ret < 0) {
		dprintk("RPC: %s map gid FAIL %d\n", __func__, ret);
		return ret;
	}

	dprintk("RPC: %s map gid to %s\n", __func__, buf);

	group = kstrdup(buf, GFP_NOFS);
	if (!group)
		return -ENOMEM;

	*groupp = group;
	return 0;
}

static int
name_cred_map_principals(struct name_cred *name_cred, struct rpc_task *task)
{
	const struct cred *cred = name_cred->nc_base.cr_cred;
	struct group_info *gi = cred->group_info;
	int ngroups;
	int ret;
	size_t i;

	ngroups = (!gi) ? 0 : gi->ngroups;

	/* check if already mapped */
	if (test_bit(AUTH_NAME_CRED_FL_MAPPED, &name_cred->nc_flags))
		return 0;

	/* try to be the one to map */
	if (test_and_set_bit(AUTH_NAME_CRED_FL_MAPPING, &name_cred->nc_flags)) {
		/* another context is mapping, wait until it's done */
		dprintk("RPC: %s wait for mapping\n", __func__);
		return -EAGAIN;
	}

	/* Did we race? */
	if (test_bit(AUTH_NAME_CRED_FL_MAPPED, &name_cred->nc_flags))
		goto out_unlock;

	ret = name_map_uid(task, cred->fsuid, &name_cred->nc_user_principal);
	if (ret)
		goto out_wake;

	ret = name_map_gid(task, cred->fsgid, &name_cred->nc_group_principal);
	if (ret)
		goto out_free_user;

	if (ngroups) {
		ret = -ENOMEM;
		name_cred->nc_other_principals = kmalloc_array(ngroups, sizeof(char *), GFP_NOFS);
		if (!name_cred->nc_other_principals)
			goto out_free_group;

		for (i = 0; i < ngroups; i++) {
			ret = name_map_gid(task, gi->gid[i],
						&name_cred->nc_other_principals[i]);
			if (ret)
				goto out_free_others;
			name_cred->nc_other_principals_count++;
		}
	}

	/* success! */
	set_bit(AUTH_NAME_CRED_FL_MAPPED, &name_cred->nc_flags);
	smp_mb__after_atomic();
out_unlock:
	clear_bit(AUTH_NAME_CRED_FL_MAPPING, &name_cred->nc_flags);
	return 0;

out_free_others:
	for (i = 0; i < name_cred->nc_other_principals_count; i++)
		kfree(name_cred->nc_other_principals[i]);
	kfree(name_cred->nc_other_principals);
	name_cred->nc_other_principals = NULL;
	name_cred->nc_other_principals_count = 0;
out_free_group:
	kfree(name_cred->nc_group_principal);
	name_cred->nc_group_principal = NULL;
out_free_user:
	kfree(name_cred->nc_user_principal);
	name_cred->nc_user_principal = NULL;
out_wake:
	clear_bit(AUTH_NAME_CRED_FL_MAPPING, &name_cred->nc_flags);
	smp_mb__after_atomic();
	dprintk("RPC: %s failed with %d\n", __func__, ret);
	return ret;
}

static struct rpc_cred *
name_create_cred(struct rpc_auth *auth, struct auth_cred *acred, int flags, gfp_t gfp)
{
	struct name_auth *name_auth = container_of(auth, struct name_auth, rpc_auth);
	struct name_cred	*name_cred = NULL;
	int err = -ENOMEM;

	dprintk("RPC:       %s for uid %d, flavor %d\n",
		__func__, from_kuid(&init_user_ns, acred->cred->fsuid),
		auth->au_flavor);

	if (!(name_cred = kzalloc(sizeof(*name_cred), gfp)))
		goto out_err;

	rpcauth_init_cred(&name_cred->nc_base, acred, auth, &name_credops);
	/*
	 * Note: in order to force a call to call_refresh(), we deliberately
	 * fail to flag the credential as RPCAUTH_CRED_UPTODATE.
	 */
	name_cred->nc_base.cr_flags = 1UL << RPCAUTH_CRED_NEW;

	name_cred_set_session(&name_cred->nc_base, NULL);

	kref_get(&name_auth->kref);
	return &name_cred->nc_base;

out_err:
	dprintk("RPC:       %s failed with error %d\n", __func__, err);
	return ERR_PTR(err);
}

static int
name_match(struct auth_cred *acred, struct rpc_cred *rc, int flags)
{
	if (test_bit(RPCAUTH_CRED_NEW, &rc->cr_flags))
		goto out;
	if (!test_bit(RPCAUTH_CRED_UPTODATE, &rc->cr_flags))
		return 0;
out:
	return cred_fscmp(rc->cr_cred, acred->cred) == 0;
}

/*
* Marshal credentials.
* Maybe we should keep a cached credential for performance reasons.
*/
static int
name_marshal(struct rpc_task *task, struct xdr_stream *xdr)
{
	__be32 *p;
	struct rpc_rqst *req = task->tk_rqstp;
	struct rpc_cred *cred = req->rq_cred;
	struct name_session *name_session;

	dprintk("RPC: %5u %s\n", task->tk_pid, __func__);

	p = xdr_reserve_space(xdr, sizeof(*p)*9);
	if (!p)
		return -EMSGSIZE;

	name_session = name_cred_get_session(cred);

	*p++ = htonl(RPC_AUTH_NAME);
	*p++ = htonl((u32) 20);
	*p++ = htonl((u32) AUTH_NAME_VERSION);

	if (name_session) {
		dprintk("RPC: %s proc %u verf %llu session_id %u\n",
			__func__, name_session->ns_proc, name_session->ns_verf,
			name_session->ns_session_id);

		*p++ = htonl((u32) name_session->ns_proc);
		p = xdr_encode_hyper(p, name_session->ns_verf);
		*p++ = htonl((u32) name_session->ns_session_id);

		name_session_put(name_session);
	} else {
		/* this should never happen */
		if (task->tk_msg.rpc_proc->p_proc != 0) {
			WARN_ON_ONCE(1);
			return -EIO;
		}
		dprintk("RPC: %s proc INIT verf 0 session_id 0\n", __func__);
		*p++ = htonl((u32) AUTH_NAME_PROC_INIT);
		p = xdr_encode_hyper(p, 0ULL);
		*p++ = htonl((u32) 0);
	}

	/* verifier is always NULL */
	*p++ = htonl(RPC_AUTH_NULL);
	*p++ = htonl(0);

	return 0;
}

static int
name_validate(struct rpc_task *task, struct xdr_stream *xdr)
{
	__be32			*p;
	u32                     size;

	p = xdr_inline_decode(xdr, 2 * sizeof(*p));
	if (!p)
		return -EIO;
	if (*p++ != rpc_auth_null)
		return -EIO;

	size = ntohl(*p++);
	if (size > RPC_MAX_AUTH_SIZE) {
		printk("RPC: giant verf size: %u\n", size);
		return -EIO;
	}
	xdr_inline_decode(xdr, size);

	return 0;
}

static int name_renew_cred(struct rpc_task *task)
{
	struct rpc_cred *oldcred = task->tk_rqstp->rq_cred;
	struct rpc_auth *auth = oldcred->cr_auth;
	struct auth_cred acred = {
		.cred = oldcred->cr_cred,
#if 0
		.principal = name_cred->nc_principal,
#endif
	};
	struct rpc_cred *new;

	printk("RPC: %s\n", __func__);
	new = name_lookup_cred(auth, &acred, RPCAUTH_LOOKUP_NEW);
	if (IS_ERR(new))
		return PTR_ERR(new);
	task->tk_rqstp->rq_cred = new;
	put_rpccred(oldcred);
	return 0;
}

static int
name_refresh_init_session(struct rpc_task *task)
{
	struct rpc_cred *cred = task->tk_rqstp->rq_cred;
	struct name_cred *name_cred = container_of(cred, struct name_cred,
							nc_base);
	int ret = 0;

	dprintk("RPC: %s\n", __func__);

	ret = name_cred_completion_alloc(name_cred);
	if (ret < 0)
		return ret;
	/* Raced? */
	if (!test_bit(RPCAUTH_CRED_NEW, &cred->cr_flags)) {
		name_cred_completion_done(name_cred);
		return 0;
	}

	if (!name_cred_completion_wait(name_cred, task))
		return 0;

	if (test_and_set_bit(RPCAUTH_CRED_INIT, &cred->cr_flags)) {
		dprintk("RPC: %s wait for init\n", __func__);
		return -EAGAIN;
	}

	if (!test_bit(RPCAUTH_CRED_NEW, &cred->cr_flags)) {
		name_cred_init_complete(name_cred);
		return 0;
	}

	ret = name_cred_map_principals(name_cred, task);
	if (ret) {
		name_cred_init_complete(name_cred);
		dprintk("RPC: %s name_cred_map_principals failed: %d\n",
			__func__, ret);
		return ret;
	}

	dprintk("RPC: %s do init\n", __func__);
	ret = rpc_ping_payload_init(task->tk_client, cred);
	dprintk("RPC: %s done with ret = %d\n", __func__, ret);

	return ret;
}

/*
* Refresh credentials.
*/
static int
name_cred_refresh(struct rpc_task *task)
{
	struct rpc_cred *cred = task->tk_rqstp->rq_cred;
	int ret = 0;

	if (!test_bit(RPCAUTH_CRED_NEW, &cred->cr_flags) &&
		!test_bit(RPCAUTH_CRED_UPTODATE, &cred->cr_flags)) {
		dprintk("RPC: %s renewpath\n", __func__);
		ret = name_renew_cred(task);
		if (ret < 0)
			goto out;
		cred = task->tk_rqstp->rq_cred;
	}

	/* ALWAYS allow NULL calls through without trying to initialize */
	if (test_bit(RPCAUTH_CRED_NEW, &cred->cr_flags) &&
	    task->tk_msg.rpc_proc->p_proc != 0) {
		ret = name_refresh_init_session(task);
		if (ret == -EAGAIN)
			task->tk_cred_retry++;
	} else
		dprintk("RPC: %s no init\n", __func__);
out:
	return ret;
}

/* Dummy refresh routine: used only when init/destroying the context */
static int
name_cred_refresh_null(struct rpc_task *task)
{
	return 0;
}

static const struct rpc_authops authname_ops = {
	.owner		= THIS_MODULE,
	.au_flavor	= RPC_AUTH_NAME,
	.au_name	= "AUTH_NAME",
	.create		= name_create,
	.destroy	= name_destroy,
	.hash_cred	= name_hash_cred,
	.lookup_cred	= name_lookup_cred,
	.crcreate	= name_create_cred,
};

static const struct rpc_credops name_credops = {
	.cr_name		= "AUTH_NAME",
	.crdestroy		= name_destroy_cred,
	.crmatch		= name_match,
	.crmarshal		= name_marshal,
	.crvalidate		= name_validate,
	.crrefresh		= name_cred_refresh,
	.crwrap_req		= rpcauth_wrap_req_encode,
	.crunwrap_resp		= rpcauth_unwrap_resp_decode,
};

static const struct rpc_credops name_destroyops = {
	.cr_name		= "AUTH_NAME",
	.crdestroy		= name_destroy_nullcred,
	.crmatch		= name_match,
	.crmarshal		= name_marshal,
	.crvalidate		= name_validate,
	.crrefresh		= name_cred_refresh_null,
	.crwrap_req		= rpcauth_wrap_req_encode,
	.crunwrap_resp		= rpcauth_unwrap_resp_decode,
};

/*
 * Initialize AUTH_NAME module
 */
static int __init init_auth_name(void)
{
	return rpcauth_register(&authname_ops);
}

static void __exit exit_auth_name(void)
{
	rpcauth_unregister(&authname_ops);
	rcu_barrier(); /* Wait for completion of call_rcu()'s */
}

MODULE_ALIAS("rpc-auth-99");
MODULE_LICENSE("GPL");

module_init(init_auth_name)
module_exit(exit_auth_name)
