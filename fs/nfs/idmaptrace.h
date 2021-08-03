/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (c) 2013 Trond Myklebust <Trond.Myklebust@netapp.com>
 */
#undef TRACE_SYSTEM
#define TRACE_SYSTEM nfs4

#if !defined(_TRACE_NFSIDMAP_H) || defined(TRACE_HEADER_MULTI_READ)
#define _TRACE_NFSIDMAP_H

#include <linux/tracepoint.h>

DECLARE_EVENT_CLASS(nfs4_idmap_event,
		TP_PROTO(
			const char *name,
			int len,
			u32 id,
			int error
		),

		TP_ARGS(name, len, id, error),

		TP_STRUCT__entry(
			__field(unsigned long, error)
			__field(u32, id)
			__dynamic_array(char, name, len > 0 ? len + 1 : 1)
		),

		TP_fast_assign(
			if (len < 0)
				len = 0;
			__entry->error = error < 0 ? error : 0;
			__entry->id = id;
			memcpy(__get_str(name), name, len);
			__get_str(name)[len] = 0;
		),

		TP_printk(
			"error=%ld id=%u name=%s",
			-__entry->error,
			__entry->id,
			__get_str(name)
		)
);
#define DEFINE_NFS4_IDMAP_EVENT(name) \
	DEFINE_EVENT(nfs4_idmap_event, name, \
			TP_PROTO( \
				const char *name, \
				int len, \
				u32 id, \
				int error \
			), \
			TP_ARGS(name, len, id, error))
DEFINE_NFS4_IDMAP_EVENT(nfs4_map_name_to_uid);
DEFINE_NFS4_IDMAP_EVENT(nfs4_map_group_to_gid);
DEFINE_NFS4_IDMAP_EVENT(nfs4_map_uid_to_name);
DEFINE_NFS4_IDMAP_EVENT(nfs4_map_gid_to_group);

#endif /* _TRACE_NFSIDMAP_H */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#define TRACE_INCLUDE_FILE idmaptrace
/* This part must be outside protection */
#include <trace/define_trace.h>
