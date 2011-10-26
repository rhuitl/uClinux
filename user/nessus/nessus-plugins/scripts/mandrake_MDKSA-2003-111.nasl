#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2003:111
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14093);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2003-t-0024");
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0962");
 
 name["english"] = "MDKSA-2003:111: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2003:111 (rsync).


A vulnerability was discovered in all versions of rsync prior to 2.5.7 that was
recently used in conjunction with the Linux kernel do_brk() vulnerability to
compromise a public rsync server.
This heap overflow vulnerability, by itself, cannot yield root access, however
it does allow arbitrary code execution on the host running rsync as a server.
Also note that this only affects hosts running rsync in server mode (listening
on port 873, typically under xinetd).


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2003:111
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the rsync package";
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
if ( rpm_check( reference:"rsync-2.5.5-5.1.90mdk", release:"MDK9.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.1.91mdk", release:"MDK9.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.7-0.1.92mdk", release:"MDK9.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"rsync-", release:"MDK9.0")
 || rpm_exists(rpm:"rsync-", release:"MDK9.1")
 || rpm_exists(rpm:"rsync-", release:"MDK9.2") )
{
 set_kb_item(name:"CVE-2003-0962", value:TRUE);
}
