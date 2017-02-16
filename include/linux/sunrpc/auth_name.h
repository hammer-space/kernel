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

/* max size of INIT payload: 256 principals / 1MB */
#define AUTH_NAME_MAX_XDRLEN ((1024 + 4) * 256)


enum auth_name_proc {
	AUTH_NAME_PROC_INIT = 0,
	AUTH_NAME_PROC_REFERENCE = 1,
	AUTH_NAME_PROC_DESTROY = 2
};

/* on-the-wire name cred: */
struct auth_name_wire_cred {
	u32			ac_v;		/* version */
	u32			ac_proc;	/* control procedure */
	u32			ac_session;	/* reference a session */
};

/* return from NULL PROC init sec context */
struct auth_name_null_init_res {
	u32			ar_status;
	u32			ar_session;
};

struct name_cred {
	struct rpc_cred		nc_base;

	/* on the wire credential state */
	enum auth_name_proc	nc_proc;
	u64			nc_verf;
	u32			nc_session;

	unsigned long		nc_flags;
#define AUTH_NAME_CRED_FL_MAPPED	0
#define AUTH_NAME_CRED_FL_MAPPING	1

	/* cached acred because mapping needs task context */
	struct auth_cred	nc_acred;

	/* principals, set when AUTH_NAME_CRED_FL_MAPPED */
	const char		*nc_user_principal;
	const char		*nc_group_principal;
	size_t			nc_other_principals_count;
	const char		**nc_other_principals;
};

#endif /* __KERNEL__ */
#endif /* _LINUX_SUNRPC_AUTH_NAME_H */
