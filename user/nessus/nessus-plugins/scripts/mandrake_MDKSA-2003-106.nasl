#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:106
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14088);
 script_bugtraq_id(8875);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0853", "CVE-2003-0854");
 
 name["english"] = "MDKSA-2003:106: fileutils/coreutils";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:106 (fileutils/coreutils).


A memory starvation denial of service vulnerability in the ls program was
discovered by Georgi Guninski. It is possible to allocate a huge amount of
memory by specifying certain command-line arguments. It is also possible to
exploit this remotely via programs that call ls such as wu-ftpd (although
wu-ftpd is no longer shipped with Mandrake Linux).
Likewise, a non-exploitable integer overflow problem was discovered in ls, which
can be used to crash ls by specifying certain command-line arguments. This can
also be triggered via remotely accessible services such as wu-ftpd.
The provided packages include a patched ls to fix these problems.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:106
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the fileutils/coreutils package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"fileutils-4.1.11-6.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"coreutils-4.5.7-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"coreutils-doc-4.5.7-1.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"coreutils-5.0-6.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"coreutils-doc-5.0-6.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"fileutils-", release:"MDK9.0")
 || rpm_exists(rpm:"fileutils-", release:"MDK9.1")
 || rpm_exists(rpm:"fileutils-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0853", value:TRUE);
 set_kb_item(name:"CVE-2003-0854", value:TRUE);
}
