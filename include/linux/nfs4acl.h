#ifndef __LINUX_NFS4ACL_H
#define __LINUX_NFS4ACL_H

int nfs4acl_who_to_special_id(const char *, u32);
bool nfs4acl_special_id_to_who(unsigned int, const char **, unsigned int *);

#endif
