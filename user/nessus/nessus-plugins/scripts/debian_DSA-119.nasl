# This script was automatically generated from the dsa-119
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Joost Pol reports that OpenSSH
versions 2.0 through 3.0.2 have an off-by-one bug in the channel allocation
code. This vulnerability can be exploited by authenticated users to gain
root privilege or by a malicious server exploiting a client with this
bug.
Since Debian 2.2 (potato) shipped with OpenSSH (the "ssh" package)
version 1.2.3, it is not vulnerable to this exploit. No fix is required
for Debian 2.2 (potato).
The Debian unstable and testing archives do include a more recent OpenSSH
(ssh) package. If you are running these pre-release distributions you should
ensure that you are running version 3.0.2p1-8, a patched version which was
added to the unstable archive today, or a later version.


Solution : http://www.debian.org/security/2002/dsa-119
Risk factor : High';

if (description) {
 script_id(14956);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "119");
 script_cve_id("CVE-2002-0083");
 script_bugtraq_id(4241);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA119] DSA-119-1 ssh");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-119-1 ssh");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (w) { security_hole(port: 0, data: desc); }
