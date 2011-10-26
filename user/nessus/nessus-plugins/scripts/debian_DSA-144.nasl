# This script was automatically generated from the dsa-144
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
A problem with wwwoffle has been discovered.  The web proxy didn\'t
handle input data with negative Content-Length settings properly which
causes the processing child to crash.  It is at this time not obvious
how this can lead to an exploitable vulnerability; however, it\'s better
to be safe than sorry, so here\'s an update.
Additionally, in the woody version empty passwords will be treated as
wrong when trying to authenticate.  In the woody version we also
replaced CanonicaliseHost() with the latest routine from 2.7d, offered
by upstream.  This stops bad IPv6 format IP addresses in URLs from
causing problems (memory overwriting, potential exploits).
This problem has been fixed in version 2.5c-10.4 for the old stable
distribution (potato), in version 2.7a-1.2 for the current stable
distribution (woody) and in version 2.7d-1 for the unstable
distribution (sid).
We recommend that you upgrade your wwwoffle packages.


Solution : http://www.debian.org/security/2002/dsa-144
Risk factor : High';

if (description) {
 script_id(14981);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "144");
 script_cve_id("CVE-2002-0818");
 script_bugtraq_id(5260);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA144] DSA-144-1 wwwoffle");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-144-1 wwwoffle");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'wwwoffle', release: '2.2', reference: '2.5c-10.4')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wwwoffle is vulnerable in Debian 2.2.\nUpgrade to wwwoffle_2.5c-10.4\n');
}
if (deb_check(prefix: 'wwwoffle', release: '3.0', reference: '2.7a-1.2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package wwwoffle is vulnerable in Debian 3.0.\nUpgrade to wwwoffle_2.7a-1.2\n');
}
if (w) { security_hole(port: 0, data: desc); }
