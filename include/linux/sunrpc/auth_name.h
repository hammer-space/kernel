/*
 * linux/include/linux/sunrpc/auth_name.h
 *
 * Declarations for AUTH_NAME
 *
 * Weston Andros Adamson <dros@monkey.org>
 *
 * Started by copying linux/include/linux/sunrpc/auth_gss.h
 *
 * Dug Song <dugsong@monkey.org>
 * Andy Adamson <andros@umich.edu>
 * Bruce Fields <bfields@umich.edu>
 * Copyright (c) 2000 The Regents of the University of Michigan
 */

#ifndef _LINUX_SUNRPC_AUTH_NAME_H
#define _LINUX_SUNRPC_AUTH_NAME_H

#ifdef __KERNEL__
#include <linux/sunrpc/auth.h>

#define AUTH_NAME_VERSION		1

#define AUTH_NAME_MAX_PRINCIPAL_LEN 1024

#define AUTH_NAME_MAX_PRINCIPAL_COUNT 256

/* max size of INIT payload: 256 principals at full size ~= 1MB */
#define AUTH_NAME_MAX_XDRLEN ((AUTH_NAME_MAX_PRINCIPAL_LEN + 4) * 256)

enum auth_name_proc {
	AUTH_NAME_PROC_INIT = 0,
	AUTH_NAME_PROC_REFERENCE = 1,
	AUTH_NAME_PROC_DESTROY = 2
};

/* return from NULL PROC init sec context */
struct auth_name_null_init_res {
	u32			ar_status;
	u32			ar_session;
};

struct name_session {
	atomic_t		ns_count;
	enum auth_name_proc	ns_proc;
	u64			ns_verf;
	u32			ns_session_id;
	struct rcu_head		ns_rcu;
};

struct name_cred {
	struct rpc_cred			nc_base;

	/* on the wire credential state */
	struct name_session __rcu	*nc_session;
	struct rpc_completion __rcu	*nc_init_completion;

	unsigned long			nc_flags;
#define AUTH_NAME_CRED_FL_MAPPED	0
#define AUTH_NAME_CRED_FL_MAPPING	1

	/* principals, set when AUTH_NAME_CRED_FL_MAPPED */
	char				*nc_user_principal;
	char				*nc_group_principal;
	size_t				nc_other_principals_count;
	char				**nc_other_principals;
};

#endif /* __KERNEL__ */
#endif /* _LINUX_SUNRPC_AUTH_NAME_H */
