# This script was automatically generated from the dsa-1022
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Several vulnerabilities have been discovered in the backup utility 
storebackup. The Common Vulnerabilities and Exposures project identifies
the following problems:
    Storebackup creates a temporary file predictably, which can be
    exploited to overwrite arbitrary files on the system with a symlink
    attack.
    The backup root directory wasn\'t created with fixed permissions, which may lead to
       inproper permissions if the umask is too lax.
    The user and group rights of symlinks are set incorrectly when making
    or restoring a backup, which may leak sensitive data.
The old stable distribution (woody) doesn\'t contain storebackup packages.
For the stable distribution (sarge) these problems have been fixed in
version 1.18.4-2sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 1.19-2.
We recommend that you upgrade your storebackup package.


Solution : http://www.debian.org/security/2006/dsa-1022
Risk factor : High';

if (description) {
 script_id(22564);
 script_version("$Revision: 1.1 $");
 script_xref(name: "DSA", value: "1022");
 script_cve_id("CVE-2005-3146", "CVE-2005-3147", "CVE-2005-3148");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2006 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA1022] DSA-1022-1 storebackup");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-1022-1 storebackup");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'storebackup', release: '', reference: '1.19-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package storebackup is vulnerable in Debian .\nUpgrade to storebackup_1.19-2\n');
}
if (deb_check(prefix: 'storebackup', release: '3.1', reference: '1.18.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package storebackup is vulnerable in Debian 3.1.\nUpgrade to storebackup_1.18.4-2sarge1\n');
}
if (deb_check(prefix: 'storebackup', release: '3.1', reference: '1.18.4-2sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package storebackup is vulnerable in Debian sarge.\nUpgrade to storebackup_1.18.4-2sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
