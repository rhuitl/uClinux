# This script was automatically generated from the dsa-279
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Paul Szabo and Matt Zimmerman discovered two similar problems in
metrics, a tools for software metrics.  Two scripts in this package,
"halstead" and "gather_stats", open temporary files without taking
appropriate security precautions.  "halstead" is installed as a user
program, while "gather_stats" is only used in an auxiliary script
included in the source code.  These vulnerabilities could allow a
local attacker to overwrite files owned by the user running the
scripts, including root.
The stable distribution (woody) is not affected since it doesn\'t
contain a metrics package anymore.
For the old stable distribution (potato) this problem has been fixed
in version 1.0-1.1.
The unstable distribution (sid) is not affected since it doesn\'t
contain a metrics package anymore.
We recommend that you upgrade your metrics package.


Solution : http://www.debian.org/security/2003/dsa-279
Risk factor : High';

if (description) {
 script_id(15116);
 script_version("$Revision: 1.6 $");
 script_xref(name: "DSA", value: "279");
 script_cve_id("CVE-2003-0202");
 script_bugtraq_id(7293);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA279] DSA-279-1 metrics");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-279-1 metrics");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'metrics', release: '2.2', reference: '1.0-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metrics is vulnerable in Debian 2.2.\nUpgrade to metrics_1.0-1.1\n');
}
if (deb_check(prefix: 'metrics', release: '2.2', reference: '1.0-1.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package metrics is vulnerable in Debian potato.\nUpgrade to metrics_1.0-1.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
