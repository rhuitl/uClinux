#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:095-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14077);
 script_version ("$Revision: 1.6 $");
 script_bugtraq_id(8679);
 script_cve_id("CVE-2003-0831");
 
 name["english"] = "MDKSA-2003:095-1: proftpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:095-1 (proftpd).


A vulnerability was discovered by X-Force Research at ISS in ProFTPD's handling
of ASCII translation. An attacker, by downloading a carefully crafted file, can
remotely exploit this bug to create a root shell.
The ProFTPD team encourages all users to upgrade to version 1.2.7 or higher. The
problematic code first appeared in ProFTPD 1.2.7rc1, and the provided packages
are all patched by the ProFTPD team to protect against this vulnerability.
Update:
The previous update had a bug where the new packages would terminate with a
SIGNAL 11 when the command 'NLST -alL' was performed in certain cases, such as
if the size of the output of the command was greater than 1024 bytes.
These updated packages have a fix applied to prevent this crash.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:095-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the proftpd package";
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
if ( rpm_check( reference:"proftpd-1.2.8-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.8-1.2.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.2.8-5.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.8-5.2.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"proftpd-", release:"MDK9.1")
 || rpm_exists(rpm:"proftpd-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0831", value:TRUE);
}
