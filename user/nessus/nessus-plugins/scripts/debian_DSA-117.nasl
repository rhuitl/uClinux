# This script was automatically generated from the dsa-117
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Kim Nielsen recently found an internal problem with the CVS server and
reported it to the vuln-dev mailing list.  The problem is triggered by
an improperly initialized global variable.  A user exploiting this can
crash the CVS server, which may be accessed through the pserver
service and running under a remote user id.  It is not yet clear if
the remote account can be exposed, though.
This problem has been fixed in version 1.10.7-9 for the stable Debian
distribution with help of Niels Heinen and in versions newer
than 1.11.1p1debian-3 for the
testing and unstable distribution of Debian (not yet uploaded,
though).
We recommend that you upgrade your CVS package.


Solution : http://www.debian.org/security/2002/dsa-117
Risk factor : High';

if (description) {
 script_id(14954);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "117");
 script_cve_id("CVE-2002-0092");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA117] DSA-117-1 cvs");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-117-1 cvs");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'cvs', release: '2.2', reference: '1.10.7-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs is vulnerable in Debian 2.2.\nUpgrade to cvs_1.10.7-9\n');
}
if (deb_check(prefix: 'cvs-doc', release: '2.2', reference: '1.10.7-9')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package cvs-doc is vulnerable in Debian 2.2.\nUpgrade to cvs-doc_1.10.7-9\n');
}
if (w) { security_hole(port: 0, data: desc); }
