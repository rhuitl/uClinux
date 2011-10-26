# This script was automatically generated from the dsa-052
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Daniel Kobras has discovered and fixed a problem in sendfiled which
caused the daemon not to drop privileges as expected when sending
notification mails. Exploiting this, a local user can easily make it
execute arbitrary code under root privileges.

We recommend that you upgrade your sendfile package immediately.



Solution : http://www.debian.org/security/2001/dsa-052
Risk factor : High';

if (description) {
 script_id(14889);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "052");
 script_cve_id("CVE-2001-0623");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA052] DSA-052-1 sendfile");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-052-1 sendfile");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'sendfile', release: '2.2', reference: '2.1-20.3')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package sendfile is vulnerable in Debian 2.2.\nUpgrade to sendfile_2.1-20.3\n');
}
if (w) { security_hole(port: 0, data: desc); }
