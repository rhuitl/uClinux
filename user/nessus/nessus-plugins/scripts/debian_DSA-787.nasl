# This script was automatically generated from the dsa-787
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '
Two bugs have been found in backup-manager, a command-line driven
backup utility.  The Common Vulnerabilities and Exposures project
identifies the following problems:
    Jeroen Vermeulen discovered that backup files are created with
    default permissions making them world readable, even though they
    may contain sensitive information.
    Sven Joachim discovered that the optional CD-burning feature of
    backup-manager uses a hardcoded filename in a world-writable
    directory for logging.  This can be subject to a symlink attack.
The old stable distribution (woody) does not provide the
backup-manager package.
For the stable distribution (sarge) these problems have been fixed in
version 0.5.7-1sarge1.
For the unstable distribution (sid) these problems have been fixed in
version 0.5.8-2.
We recommend that you upgrade your backup-manager package.


Solution : http://www.debian.org/security/2005/dsa-787
Risk factor : High';

if (description) {
 script_id(19530);
 script_version("$Revision: 1.2 $");
 script_xref(name: "DSA", value: "787");
 script_cve_id("CVE-2005-1855", "CVE-2005-1856");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA787] DSA-787-1 backup-manager");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-787-1 backup-manager");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'backup', release: '', reference: '0.5.8-2')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package backup is vulnerable in Debian .\nUpgrade to backup_0.5.8-2\n');
}
if (deb_check(prefix: 'backup-manager', release: '3.1', reference: '0.5.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package backup-manager is vulnerable in Debian 3.1.\nUpgrade to backup-manager_0.5.7-1sarge1\n');
}
if (deb_check(prefix: 'backup', release: '3.1', reference: '0.5.7-1sarge1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package backup is vulnerable in Debian sarge.\nUpgrade to backup_0.5.7-1sarge1\n');
}
if (w) { security_hole(port: 0, data: desc); }
