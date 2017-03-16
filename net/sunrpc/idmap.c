/*
 *  UID and GID to name mapping for clients.
 *
 *  Copyright (c) 2002 The Regents of the University of Michigan.
 *  All rights reserved.
 *
 *  Marius Aamodt Eriksen <marius@umich.edu>
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
#include <linux/types.h>
#include <linux/parser.h>
#include <linux/fs.h>
#include <net/net_namespace.h>
#include <linux/sunrpc/rpc_pipe_fs.h>
#include <linux/sunrpc/idmap.h>
#include <linux/key.h>
#include <linux/keyctl.h>
#include <linux/key-type.h>
#include <keys/user-type.h>
#include <linux/module.h>
#include <trace/events/sunrpc.h>

#include "netns.h"

#if IS_ENABLED(CONFIG_SUNRPC_DEBUG)
# define RPCDBG_FACILITY        RPCDBG_CALL
#endif

#define SUNRPC_UINT_MAXLEN 11

static const struct cred *id_resolver_cache;
static struct key_type key_type_id_resolver_legacy;
unsigned int sunrpc_idmap_cache_timeout = 600;

struct sunrpc_idmap_legacy_upcalldata {
	struct rpc_pipe_msg pipe_msg;
	struct sunrpc_idmap_msg idmap_msg;
	struct key  *authkey;
	struct idmap *idmap;
};

struct idmap {
	struct rpc_pipe_dir_object idmap_pdo;
	struct rpc_pipe		*idmap_pipe;
	struct sunrpc_idmap_legacy_upcalldata *idmap_upcall_data;
	struct mutex		idmap_mutex;
};

int sunrpc_idmap_string_to_numeric(const char *name, size_t namelen, __u32 *res)
{
	unsigned long val;
	char buf[16];

	if (memchr(name, '@', namelen) != NULL || namelen >= sizeof(buf))
		return 0;
	memcpy(buf, name, namelen);
	buf[namelen] = '\0';
	if (kstrtoul(buf, 0, &val) != 0)
		return 0;
	*res = val;
	return 1;
}
EXPORT_SYMBOL_GPL(sunrpc_idmap_string_to_numeric);

static int sunrpc_idmap_numeric_to_string(__u32 id, char *buf, size_t buflen)
{
	return snprintf(buf, buflen, "%u", id);
}

static struct key_type key_type_id_resolver = {
	.name		= "id_resolver",
	.preparse	= user_preparse,
	.free_preparse	= user_free_preparse,
	.instantiate	= generic_key_instantiate,
	.revoke		= user_revoke,
	.destroy	= user_destroy,
	.describe	= user_describe,
	.read		= user_read,
};

static int sunrpc_idmap_init_keyring(void)
{
	struct cred *cred;
	struct key *keyring;
	int ret = 0;

	printk(KERN_NOTICE "SUNRPC: Registering the %s key type\n",
		key_type_id_resolver.name);

	cred = prepare_kernel_cred(NULL);
	if (!cred)
		return -ENOMEM;

	keyring = keyring_alloc(".id_resolver",
				GLOBAL_ROOT_UID, GLOBAL_ROOT_GID, cred,
				(KEY_POS_ALL & ~KEY_POS_SETATTR) |
				KEY_USR_VIEW | KEY_USR_READ,
				KEY_ALLOC_NOT_IN_QUOTA, NULL, NULL);
	if (IS_ERR(keyring)) {
		ret = PTR_ERR(keyring);
		goto failed_put_cred;
	}

	ret = register_key_type(&key_type_id_resolver);
	if (ret < 0)
		goto failed_put_key;

	ret = register_key_type(&key_type_id_resolver_legacy);
	if (ret < 0)
		goto failed_reg_legacy;

	set_bit(KEY_FLAG_ROOT_CAN_CLEAR, &keyring->flags);
	cred->thread_keyring = keyring;
	cred->jit_keyring = KEY_REQKEY_DEFL_THREAD_KEYRING;
	id_resolver_cache = cred;
	return 0;

failed_reg_legacy:
	unregister_key_type(&key_type_id_resolver);
failed_put_key:
	key_put(keyring);
failed_put_cred:
	put_cred(cred);
	return ret;
}

static void sunrpc_idmap_quit_keyring(void)
{
	key_revoke(id_resolver_cache->thread_keyring);
	unregister_key_type(&key_type_id_resolver);
	unregister_key_type(&key_type_id_resolver_legacy);
	put_cred(id_resolver_cache);
}

/*
 * Assemble the description to pass to request_key()
 * This function will allocate a new string and update dest to point
 * at it.  The caller is responsible for freeing dest.
 *
 * On error 0 is returned.  Otherwise, the length of dest is returned.
 */
static ssize_t sunrpc_idmap_get_desc(const char *name, size_t namelen,
				const char *type, size_t typelen, char **desc)
{
	char *cp;
	size_t desclen = typelen + namelen + 2;

	*desc = kmalloc(desclen, GFP_KERNEL);
	if (!*desc)
		return -ENOMEM;

	cp = *desc;
	memcpy(cp, type, typelen);
	cp += typelen;
	*cp++ = ':';

	memcpy(cp, name, namelen);
	cp += namelen;
	*cp = '\0';
	return desclen;
}

static struct key *sunrpc_idmap_request_key(const char *name, size_t namelen,
					 const char *type, struct idmap *idmap)
{
	char *desc;
	struct key *rkey;
	ssize_t ret;

	ret = sunrpc_idmap_get_desc(name, namelen, type, strlen(type), &desc);
	if (ret <= 0)
		return ERR_PTR(ret);

	rkey = request_key(&key_type_id_resolver, desc, "");
	if (IS_ERR(rkey)) {
		mutex_lock(&idmap->idmap_mutex);
		rkey = request_key_with_auxdata(&key_type_id_resolver_legacy,
						desc, "", 0, idmap);
		mutex_unlock(&idmap->idmap_mutex);
	}
	if (!IS_ERR(rkey))
		set_bit(KEY_FLAG_ROOT_CAN_INVAL, &rkey->flags);

	kfree(desc);
	return rkey;
}

static ssize_t sunrpc_idmap_get_key(const char *name, size_t namelen,
				 const char *type, void *data,
				 size_t data_size, struct idmap *idmap)
{
	const struct cred *saved_cred;
	struct key *rkey;
	struct user_key_payload *payload;
	ssize_t ret;

	dprintk("RPC: %s\n", __func__);

	saved_cred = override_creds(id_resolver_cache);
	rkey = sunrpc_idmap_request_key(name, namelen, type, idmap);
	revert_creds(saved_cred);

	if (IS_ERR(rkey)) {
		ret = PTR_ERR(rkey);
		dprintk("RPC: %s err 1 %d\n", __func__, ret);
		goto out;
	}

	rcu_read_lock();
	rkey->perm |= KEY_USR_VIEW;

	ret = key_validate(rkey);
	if (ret < 0) {
		dprintk("RPC: %s err 2 %d\n", __func__, ret);
		goto out_up;
	}

	payload = dereference_key_rcu(rkey);
	if (IS_ERR_OR_NULL(payload)) {
		ret = PTR_ERR(payload);
		dprintk("RPC: %s err 3 %d\n", __func__, ret);
		goto out_up;
	}

	ret = payload->datalen;
	if (ret > 0 && ret <= data_size)
		memcpy(data, payload->data, ret);
	else {
		ret = -EINVAL;
		dprintk("RPC: %s err 4 %d\n", __func__, ret);
	}

out_up:
	rcu_read_unlock();
	key_put(rkey);
out:
	return ret;
}

/* ID -> Name */
static ssize_t sunrpc_idmap_lookup_name(__u32 id, const char *type, char *buf,
				     size_t buflen, struct idmap *idmap)
{
	char id_str[SUNRPC_UINT_MAXLEN];
	int id_len;
	ssize_t ret;

	dprintk("RPC: %s\n", __func__);
	id_len = snprintf(id_str, sizeof(id_str), "%u", id);
	ret = sunrpc_idmap_get_key(id_str, id_len, type, buf, buflen, idmap);
	dprintk("RPC: %s ret %d\n", __func__, ret);
	if (ret < 0)
		return -EINVAL;
	return ret;
}

/* Name -> ID */
/* Returns -ENOENT for unknown names (with @id set to the nobody id). */
static int sunrpc_idmap_lookup_id(const char *name, size_t namelen, const char *type,
			       __u32 *id, struct idmap *idmap)
{
	char id_str[SUNRPC_UINT_MAXLEN + 1];
	long id_long;
	ssize_t data_size;
	int ret = 0;

	data_size = sunrpc_idmap_get_key(name, namelen, type, id_str, sizeof(id_str), idmap);
	if (data_size <= 0) {
		ret = -EINVAL;
	} else {
		ret = kstrtol(id_str, 10, &id_long);
		*id = (__u32)id_long;
		if (!ret && *id_str != '+')
			ret = -ENOENT;
	}
	return ret;
}

/* idmap classic begins here */

enum {
	Opt_find_uid, Opt_find_gid, Opt_find_user, Opt_find_group, Opt_find_err
};

static const match_table_t sunrpc_idmap_tokens = {
	{ Opt_find_uid, "uid:%s" },
	{ Opt_find_gid, "gid:%s" },
	{ Opt_find_user, "user:%s" },
	{ Opt_find_group, "group:%s" },
	{ Opt_find_err, NULL }
};

static int sunrpc_idmap_legacy_upcall(struct key *, void *);
static ssize_t sunrpc_idmap_pipe_downcall(struct file *, const char __user *,
				   size_t);
static void sunrpc_idmap_release_pipe(struct inode *);
static void sunrpc_idmap_pipe_destroy_msg(struct rpc_pipe_msg *);

static const struct rpc_pipe_ops sunrpc_idmap_upcall_ops = {
	.upcall		= rpc_pipe_generic_upcall,
	.downcall	= sunrpc_idmap_pipe_downcall,
	.release_pipe	= sunrpc_idmap_release_pipe,
	.destroy_msg	= sunrpc_idmap_pipe_destroy_msg,
};

static struct key_type key_type_id_resolver_legacy = {
	.name		= "id_legacy",
	.preparse	= user_preparse,
	.free_preparse	= user_free_preparse,
	.instantiate	= generic_key_instantiate,
	.revoke		= user_revoke,
	.destroy	= user_destroy,
	.describe	= user_describe,
	.read		= user_read,
	.request_key	= sunrpc_idmap_legacy_upcall,
};

static void sunrpc_idmap_pipe_destroy(struct dentry *dir,
		struct rpc_pipe_dir_object *pdo)
{
	struct idmap *idmap = pdo->pdo_data;
	struct rpc_pipe *pipe = idmap->idmap_pipe;

	if (pipe->dentry) {
		rpc_unlink(pipe->dentry);
		pipe->dentry = NULL;
	}
}

static int sunrpc_idmap_pipe_create(struct dentry *dir,
		struct rpc_pipe_dir_object *pdo)
{
	struct idmap *idmap = pdo->pdo_data;
	struct rpc_pipe *pipe = idmap->idmap_pipe;
	struct dentry *dentry;

	dentry = rpc_mkpipe_dentry(dir, "idmap", idmap, pipe);
	if (IS_ERR(dentry))
		return PTR_ERR(dentry);
	pipe->dentry = dentry;
	return 0;
}

static const struct rpc_pipe_dir_object_ops sunrpc_idmap_pipe_dir_object_ops = {
	.create = sunrpc_idmap_pipe_create,
	.destroy = sunrpc_idmap_pipe_destroy,
};

int
sunrpc_idmap_new(struct rpc_clnt *clnt)
{
	struct idmap *idmap;
	struct rpc_pipe *pipe;
	int error;

	idmap = kzalloc(sizeof(*idmap), GFP_KERNEL);
	if (idmap == NULL)
		return -ENOMEM;

	rpc_init_pipe_dir_object(&idmap->idmap_pdo,
			&sunrpc_idmap_pipe_dir_object_ops,
			idmap);

	pipe = rpc_mkpipe_data(&sunrpc_idmap_upcall_ops, 0);
	if (IS_ERR(pipe)) {
		error = PTR_ERR(pipe);
		goto err;
	}
	idmap->idmap_pipe = pipe;
	mutex_init(&idmap->idmap_mutex);

	error = rpc_add_pipe_dir_object(rpc_net_ns(clnt),
			&clnt->cl_pipedir_objects,
			&idmap->idmap_pdo);
	if (error)
		goto err_destroy_pipe;

	clnt->cl_idmap = idmap;
	return 0;
err_destroy_pipe:
	rpc_destroy_pipe_data(idmap->idmap_pipe);
err:
	kfree(idmap);
	return error;
}

void
sunrpc_idmap_delete(struct rpc_clnt *clnt)
{
	struct idmap *idmap = clnt->cl_idmap;

	if (!idmap)
		return;
	clnt->cl_idmap = NULL;
	rpc_remove_pipe_dir_object(rpc_net_ns(clnt),
			&clnt->cl_pipedir_objects,
			&idmap->idmap_pdo);
	rpc_destroy_pipe_data(idmap->idmap_pipe);
	kfree(idmap);
}

int sunrpc_idmap_init(void)
{
	return sunrpc_idmap_init_keyring();
}

void sunrpc_idmap_quit(void)
{
	sunrpc_idmap_quit_keyring();
}

static int sunrpc_idmap_prepare_message(char *desc, struct idmap *idmap,
				     struct sunrpc_idmap_msg *im,
				     struct rpc_pipe_msg *msg)
{
	substring_t substr;
	int token, ret;

	im->im_type = IDMAP_TYPE_GROUP;
	token = match_token(desc, sunrpc_idmap_tokens, &substr);

	switch (token) {
	case Opt_find_uid:
		im->im_type = IDMAP_TYPE_USER;
	case Opt_find_gid:
		im->im_conv = IDMAP_CONV_NAMETOID;
		ret = match_strlcpy(im->im_name, &substr, IDMAP_NAMESZ);
		break;

	case Opt_find_user:
		im->im_type = IDMAP_TYPE_USER;
	case Opt_find_group:
		im->im_conv = IDMAP_CONV_IDTONAME;
		ret = match_int(&substr, &im->im_id);
		break;

	default:
		ret = -EINVAL;
		goto out;
	}

	msg->data = im;
	msg->len  = sizeof(struct sunrpc_idmap_msg);

out:
	return ret;
}

static bool
sunrpc_idmap_prepare_pipe_upcall(struct idmap *idmap,
		struct sunrpc_idmap_legacy_upcalldata *data)
{
	if (idmap->idmap_upcall_data != NULL) {
		WARN_ON_ONCE(1);
		return false;
	}
	idmap->idmap_upcall_data = data;
	return true;
}

static void
sunrpc_idmap_complete_pipe_upcall_locked(struct idmap *idmap, int ret)
{
	struct key *authkey = idmap->idmap_upcall_data->authkey;

	kfree(idmap->idmap_upcall_data);
	idmap->idmap_upcall_data = NULL;
	complete_request_key(authkey, ret);
	key_put(authkey);
}

static void
sunrpc_idmap_abort_pipe_upcall(struct idmap *idmap, int ret)
{
	if (idmap->idmap_upcall_data != NULL)
		sunrpc_idmap_complete_pipe_upcall_locked(idmap, ret);
}

static int sunrpc_idmap_legacy_upcall(struct key *authkey, void *aux)
{
	struct sunrpc_idmap_legacy_upcalldata *data;
	struct request_key_auth *rka = get_request_key_auth(authkey);
	struct rpc_pipe_msg *msg;
	struct sunrpc_idmap_msg *im;
	struct idmap *idmap = (struct idmap *)aux;
	struct key *key = rka->target_key;
	int ret = -ENOMEM;

	/* msg and im are freed in sunrpc_idmap_pipe_destroy_msg */
	data = kzalloc(sizeof(*data), GFP_KERNEL);
	if (!data)
		goto out1;

	msg = &data->pipe_msg;
	im = &data->idmap_msg;
	data->idmap = idmap;
	data->authkey = key_get(authkey);

	ret = sunrpc_idmap_prepare_message(key->description, idmap, im, msg);
	if (ret < 0)
		goto out2;

	ret = -EAGAIN;
	if (!sunrpc_idmap_prepare_pipe_upcall(idmap, data))
		goto out2;

	ret = rpc_queue_upcall(idmap->idmap_pipe, msg);
	if (ret < 0)
		sunrpc_idmap_abort_pipe_upcall(idmap, ret);

	return ret;
out2:
	kfree(data);
out1:
	complete_request_key(authkey, ret);
	return ret;
}

static int sunrpc_idmap_instantiate(struct key *key, struct key *authkey, char *data, size_t datalen)
{
	return key_instantiate_and_link(key, data, datalen,
					id_resolver_cache->thread_keyring,
					authkey);
}

static int sunrpc_idmap_read_and_verify_message(struct sunrpc_idmap_msg *im,
		struct sunrpc_idmap_msg *upcall,
		struct key *key, struct key *authkey)
{
	char id_str[SUNRPC_UINT_MAXLEN];
	size_t len;
	int ret = -ENOKEY;

	/* ret = -ENOKEY */
	if (upcall->im_type != im->im_type || upcall->im_conv != im->im_conv)
		goto out;
	switch (im->im_conv) {
	case IDMAP_CONV_NAMETOID:
		if (strcmp(upcall->im_name, im->im_name) != 0)
			break;
		/* Note: here we store the NUL terminator too */
		len = sprintf(id_str, "%d", im->im_id) + 1;
		ret = sunrpc_idmap_instantiate(key, authkey, id_str, len);
		break;
	case IDMAP_CONV_IDTONAME:
		if (upcall->im_id != im->im_id)
			break;
		len = strlen(im->im_name);
		ret = sunrpc_idmap_instantiate(key, authkey, im->im_name, len);
		break;
	default:
		ret = -EINVAL;
	}
out:
	return ret;
}

static ssize_t
sunrpc_idmap_pipe_downcall(struct file *filp, const char __user *src, size_t mlen)
{
	struct request_key_auth *rka;
	struct rpc_inode *rpci = RPC_I(file_inode(filp));
	struct idmap *idmap = (struct idmap *)rpci->private;
	struct key *authkey;
	struct sunrpc_idmap_msg im;
	size_t namelen_in;
	int ret = -ENOKEY;

	/* If instantiation is successful, anyone waiting for key construction
	 * will have been woken up and someone else may now have used
	 * idmap_key_cons - so after this point we may no longer touch it.
	 */
	if (idmap->idmap_upcall_data == NULL)
		goto out_noupcall;

	authkey = idmap->idmap_upcall_data->authkey;
	rka = get_request_key_auth(authkey);;

	if (mlen != sizeof(im)) {
		ret = -ENOSPC;
		goto out;
	}

	if (copy_from_user(&im, src, mlen) != 0) {
		ret = -EFAULT;
		goto out;
	}

	if (!(im.im_status & IDMAP_STATUS_SUCCESS)) {
		ret = -ENOKEY;
		goto out;
	}

	namelen_in = strnlen(im.im_name, IDMAP_NAMESZ);
	if (namelen_in == 0 || namelen_in == IDMAP_NAMESZ) {
		ret = -EINVAL;
		goto out;
	}

	ret = sunrpc_idmap_read_and_verify_message(&im,
			&idmap->idmap_upcall_data->idmap_msg,
			rka->target_key, authkey);
	if (ret >= 0) {
		key_set_timeout(rka->target_key, sunrpc_idmap_cache_timeout);
		ret = mlen;
	}

out:
	sunrpc_idmap_complete_pipe_upcall_locked(idmap, ret);
out_noupcall:
	return ret;
}

static void
sunrpc_idmap_pipe_destroy_msg(struct rpc_pipe_msg *msg)
{
	struct sunrpc_idmap_legacy_upcalldata *data = container_of(msg,
			struct sunrpc_idmap_legacy_upcalldata,
			pipe_msg);
	struct idmap *idmap = data->idmap;

	if (msg->errno)
		sunrpc_idmap_abort_pipe_upcall(idmap, msg->errno);
}

static void
sunrpc_idmap_release_pipe(struct inode *inode)
{
	struct rpc_inode *rpci = RPC_I(inode);
	struct idmap *idmap = (struct idmap *)rpci->private;

	sunrpc_idmap_abort_pipe_upcall(idmap, -EPIPE);
}

int sunrpc_idmap_name_to_uid(struct rpc_clnt *clnt, const char *name, size_t namelen, kuid_t *uid)
{
	struct idmap *idmap = clnt->cl_idmap;
	__u32 id = -1;
	int ret = 0;

	if (!sunrpc_idmap_string_to_numeric(name, namelen, &id)) {
		const char *type;

		for(;;) {
			type = "xuid";
			if (test_bit(RPC_CLNT_IDMAP_FLAGS_NOXUID, &clnt->cl_idmap_flags))
				type = "uid";

			ret = sunrpc_idmap_lookup_id(name, namelen, type, &id, idmap);
			if (ret != -EINVAL || test_bit(RPC_CLNT_IDMAP_FLAGS_NOXUID, &clnt->cl_idmap_flags))
				break;
			printk(KERN_NOTICE "SUNRPC: Falling back from idmap "
			       "xuid/xgid to uid/gid\n");
			set_bit(RPC_CLNT_IDMAP_FLAGS_NOXUID, &clnt->cl_idmap_flags);
		}
	}
	if (ret == 0 || ret == -ENOENT) {
		*uid = make_kuid(&init_user_ns, id);
		if (!uid_valid(*uid))
			ret = -ERANGE;
	}
	trace_sunrpc_map_name_to_uid(name, namelen, id, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(sunrpc_idmap_name_to_uid);

int sunrpc_idmap_group_to_gid(struct rpc_clnt *clnt, const char *name, size_t namelen, kgid_t *gid)
{
	struct idmap *idmap = clnt->cl_idmap;
	__u32 id = -1;
	int ret = 0;

	if (!sunrpc_idmap_string_to_numeric(name, namelen, &id)) {
		const char *type;

		for(;;) {
			type = "xgid";
			if (test_bit(RPC_CLNT_IDMAP_FLAGS_NOXUID, &clnt->cl_idmap_flags))
				type = "gid";

			ret = sunrpc_idmap_lookup_id(name, namelen, type, &id, idmap);
			if (ret != -EINVAL || test_bit(RPC_CLNT_IDMAP_FLAGS_NOXUID, &clnt->cl_idmap_flags))
				break;
			printk(KERN_NOTICE "SUNRPC: Falling back from idmap "
			       "xuid/xgid to uid/gid\n");
			set_bit(RPC_CLNT_IDMAP_FLAGS_NOXUID, &clnt->cl_idmap_flags);
		}
	}
	if (ret == 0 || ret == -ENOENT) {
		*gid = make_kgid(&init_user_ns, id);
		if (!gid_valid(*gid))
			ret = -ERANGE;
	}
	trace_sunrpc_map_group_to_gid(name, namelen, id, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(sunrpc_idmap_group_to_gid);

int sunrpc_idmap_uid_to_name(const struct rpc_clnt *clnt, kuid_t uid, char *buf, size_t buflen, bool nomap)
{
	struct idmap *idmap = clnt->cl_idmap;
	int ret = -EINVAL;
	__u32 id;

	dprintk("RPC: %s, %lu inomap=%d\n", __func__, uid, nomap);

	id = from_kuid(&init_user_ns, uid);
	if (!nomap)
		ret = sunrpc_idmap_lookup_name(id, "user", buf, buflen, idmap);
	if (ret < 0)
		ret = sunrpc_idmap_numeric_to_string(id, buf, buflen);
	dprintk("RPC: %s ret %d\n", __func__, ret);
	trace_sunrpc_map_uid_to_name(buf, ret, id, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(sunrpc_idmap_uid_to_name);

int sunrpc_idmap_gid_to_group(const struct rpc_clnt *clnt, kgid_t gid, char *buf, size_t buflen, bool nomap)
{
	struct idmap *idmap = clnt->cl_idmap;
	int ret = -EINVAL;
	__u32 id;

	id = from_kgid(&init_user_ns, gid);
	if (!nomap)
		ret = sunrpc_idmap_lookup_name(id, "group", buf, buflen, idmap);
	if (ret < 0)
		ret = sunrpc_idmap_numeric_to_string(id, buf, buflen);
	trace_sunrpc_map_gid_to_group(buf, ret, id, ret);
	return ret;
}
EXPORT_SYMBOL_GPL(sunrpc_idmap_gid_to_group);
