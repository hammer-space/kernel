#include <linux/fs.h>
#include <linux/richacl.h>
#include <linux/nfs4acl.h>

static struct special_id {
	char *who;
	int   len;
} special_who_map[] = {
	[RICHACE_OWNER_SPECIAL_ID] = {
		.who = "OWNER@",
		.len = sizeof("OWNER@") - 1 },
	[RICHACE_GROUP_SPECIAL_ID] = {
		.who = "GROUP@",
		.len = sizeof("GROUP@") - 1 },
	[RICHACE_EVERYONE_SPECIAL_ID] = {
		.who = "EVERYONE@",
		.len = sizeof("EVERYONE@") - 1 }
};

int nfs4acl_who_to_special_id(const char *who, u32 len)
{
	int n;

	for (n = 0; n < ARRAY_SIZE(special_who_map); n++) {
		if (len == special_who_map[n].len &&
		    !memcmp(who, special_who_map[n].who, len))
			return n;
	}
	return -1;
}
EXPORT_SYMBOL(nfs4acl_who_to_special_id);

bool nfs4acl_special_id_to_who(unsigned int special_who,
			       const char **who, unsigned int *len)
{
	struct special_id *special = &special_who_map[special_who];

	if (special_who > ARRAY_SIZE(special_who_map) || !special->len)
		return false;
	*who = special->who;
	*len = special->len;
	return true;
}
EXPORT_SYMBOL(nfs4acl_special_id_to_who);
