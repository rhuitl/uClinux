# This script was automatically generated from the dsa-260
# Debian Security Advisory
# It is released under the Nessus Script Licence.
# Advisory is copyright 1997-2004 Software in the Public Interest, Inc.
# See http://www.debian.org/license
# DSA2nasl Convertor is copyright 2004 Michel Arboi

if (! defined_func('bn_random')) exit(0);

desc = '

iDEFENSE discovered a buffer overflow vulnerability in the ELF format
parsing of the "file" command, one which can be used to execute
arbitrary code with the privileges of the user running the command. The
vulnerability can be exploited by crafting a special ELF binary which is
then input to file. This could be accomplished by leaving the binary on
the file system and waiting for someone to use file to identify it, or
by passing it to a service that uses file to classify input. (For
example, some printer filters run file to determine how to process input
going to a printer.)
Fixed packages are available in version 3.28-1.potato.1 for Debian 2.2
(potato) and version 3.37-3.1.woody.1 for Debian 3.0 (woody). We
recommend you upgrade your file package immediately.


Solution : http://www.debian.org/security/2003/dsa-260
Risk factor : High';

if (description) {
 script_id(15097);
 script_version("$Revision: 1.5 $");
 script_xref(name: "DSA", value: "260");
 script_cve_id("CVE-2003-0102");

 script_description(english: desc);
 script_copyright(english: "This script is (C) 2005 Michel Arboi <mikhail@nessus.org>");
 script_name(english: "[DSA260] DSA-260-1 file");
 script_category(ACT_GATHER_INFO);
 script_family(english: "Debian Local Security Checks");
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Debian/dpkg-l");
 script_summary(english: "DSA-260-1 file");
 exit(0);
}

include("debian_package.inc");

w = 0;
if (deb_check(prefix: 'file', release: '2.2', reference: '3.28-1.potato.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package file is vulnerable in Debian 2.2.\nUpgrade to file_3.28-1.potato.1\n');
}
if (deb_check(prefix: 'file', release: '3.0', reference: '3.37-3.1.woody.1')) {
 w ++;
 if (report_verbosity > 0) desc = strcat(desc, '\nThe package file is vulnerable in Debian 3.0.\nUpgrade to file_3.37-3.1.woody.1\n');
}
if (w) { security_hole(port: 0, data: desc); }
