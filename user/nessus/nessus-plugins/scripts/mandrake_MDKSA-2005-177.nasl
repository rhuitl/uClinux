#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2005:177
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19985);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2005-3069", "CVE-2005-3070");
 
 name["english"] = "MDKSA-2005:177: hylafax";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2005:177 (hylafax).



faxcron, recvstats, and xferfaxstats in HylaFax 4.2.1 and earlier allows local
users to overwrite arbitrary files via a symlink attack on temporary files.
(CVE-2005-3069)

In addition, HylaFax has some provisional support for Unix domain sockets,
which is disabled in the default compile configuration. It is suspected that a
local user could create a fake /tmp/hyla.unix socket and intercept fax traffic
via this socket. In testing for this vulnerability, with CONFIG_UNIXTRANSPORT
disabled, it has been found that client programs correctly exit before sending
any data. (CVE-2005-3070)

The updated packages have been patched to correct these issues.



Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2005:177
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the hylafax package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Mandrake Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/Mandrake/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"hylafax-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.0-1.3.101mdk", release:"MDK10.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.0-3.1.102mdk", release:"MDK10.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-client-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"hylafax-server-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"libhylafax4.2.0-devel-4.2.1-2.1.20060mdk", release:"MDK2006.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"hylafax-", release:"MDK10.1")
 || rpm_exists(rpm:"hylafax-", release:"MDK10.2")
 || rpm_exists(rpm:"hylafax-", release:"MDK2006.0") )
{
 set_kb_item(name:"CVE-2005-3069", value:TRUE);
 set_kb_item(name:"CVE-2005-3070", value:TRUE);
}
