# This script was automatically generated from the dsa-142
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
An integer overflow bug has been discovered in the RPC library used by
the OpenAFS database server, which is derived from the SunRPC library.
This bug could be exploited to crash certain OpenAFS servers
(volserver, vlserver, ptserver, buserver) or to obtain unauthorized
root access to a host running one of these processes.  No exploits are
known to exist yet.
This problem has been fixed in version 1.2.3final2-6 for the current
stable distribution (woody) and in version 1.2.6-1 for the unstable
distribution (sid).  Debian 2.2 (potato) is not affected since it
doesn\'t contain OpenAFS packages.
OpenAFS is only available for the architectures alpha, i386, powerpc,
s390, sparc.  Hence, we only provide fixed packages for these
architectures.
We recommend that you upgrade your openafs packages.


Solution : http://www.debian.org/security/2002/dsa-142
Risk factor : High';

if (description) {
 script_id(14979);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2002-t-0015");
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "142");
 script_cve_id("CVE-2002-0391");
 script_bugtraq_id(5356);
 script_xref(name: "CERT", value: "192995");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA142] DSA-142-1 openafs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-142-1 openafs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'libopenafs-dev', release: '3.0', reference: '1.2.3final2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package libopenafs-dev is vulnerable in Debian 3.0.\nUpgrade to libopenafs-dev_1.2.3final2-6\n');
}
if (deb_check(prefix: 'openafs-client', release: '3.0', reference: '1.2.3final2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openafs-client is vulnerable in Debian 3.0.\nUpgrade to openafs-client_1.2.3final2-6\n');
}
if (deb_check(prefix: 'openafs-dbserver', release: '3.0', reference: '1.2.3final2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openafs-dbserver is vulnerable in Debian 3.0.\nUpgrade to openafs-dbserver_1.2.3final2-6\n');
}
if (deb_check(prefix: 'openafs-fileserver', release: '3.0', reference: '1.2.3final2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openafs-fileserver is vulnerable in Debian 3.0.\nUpgrade to openafs-fileserver_1.2.3final2-6\n');
}
if (deb_check(prefix: 'openafs-kpasswd', release: '3.0', reference: '1.2.3final2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openafs-kpasswd is vulnerable in Debian 3.0.\nUpgrade to openafs-kpasswd_1.2.3final2-6\n');
}
if (deb_check(prefix: 'openafs-modules-source', release: '3.0', reference: '1.2.3final2-6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package openafs-modules-source is vulnerable in Debian 3.0.\nUpgrade to openafs-modules-source_1.2.3final2-6\n');
}
if (w) { security_hole(port: 0, data: desc); }
