# This script was automatically generated from the dsa-036
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = 'It has been reported that a local user could tweak
Midnight Commander of another user into executing an arbitrary program under
the user id of the person running Midnight Commander.  This behaviour has been
fixed by Andrew V. Samoilov.

We recommend you upgrade your mc package.


Solution : http://www.debian.org/security/2001/dsa-036
Risk factor : High';

if (description) {
 script_id(14873);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "036");
 script_cve_id("CVE-2000-1109");
 script_bugtraq_id(2016);

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA036] DSA-036-1 Midnight Commander");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-036-1 Midnight Commander");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'gmc', release: '2.2', reference: '4.5.42-11.potato.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package gmc is vulnerable in Debian 2.2.\nUpgrade to gmc_4.5.42-11.potato.6\n');
}
if (deb_check(prefix: 'mc', release: '2.2', reference: '4.5.42-11.potato.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc is vulnerable in Debian 2.2.\nUpgrade to mc_4.5.42-11.potato.6\n');
}
if (deb_check(prefix: 'mc-common', release: '2.2', reference: '4.5.42-11.potato.6')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package mc-common is vulnerable in Debian 2.2.\nUpgrade to mc-common_4.5.42-11.potato.6\n');
}
if (w) { security_hole(port: 0, data: desc); }
