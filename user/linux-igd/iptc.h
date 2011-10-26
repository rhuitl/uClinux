#ifndef _IPTC_H_
	#define _IPTC_H_

void iptc_add_rule(const char *table,
                   const char *chain,
                   const char *protocol,
                   const char *iiface,
                   const char *oiface,
                   const char *src,
                   const char *dest,
                   const char *srcports,
                   const char *destports,
                   const char *target,
                   const char *dnat_to,
                   const int append);

void iptc_delete_rule(const char *table,
                      const char *chain,
                      const char *protocol,
                      const char *iniface,
                      const char *outiface,
                      const char *src,
                      const char *dest,
                      const char *srcports,
                      const char *destports,
                      const char *target,
                      const char *dnat_to);

#endif // _IPTC_H_
