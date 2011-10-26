#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:051
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13954);
 script_bugtraq_id(4376);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2002-0382");
 
 name["english"] = "MDKSA-2002:051: xchat";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:051 (xchat).


In versions of the xchat IRC client prior to version 1.8.9, xchat does not
filter the response from an IRC server when a /dns query is executed. xchat
resolves hostnames by passing the configured resolver and hostname to a shell,
so an IRC server may return a malicious response formatted so that arbitrary
commands are executed with the privilege of the user running xchat.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:051
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the xchat package";
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
if ( rpm_check( reference:"xchat-1.8.9-1.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-1.8.9-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-1.8.9-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-1.8.9-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-1.8.9-1.1mdk", release:"MDK8.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if (rpm_exists(rpm:"xchat-", release:"MDK7.1")
 || rpm_exists(rpm:"xchat-", release:"MDK7.2")
 || rpm_exists(rpm:"xchat-", release:"MDK8.0")
 || rpm_exists(rpm:"xchat-", release:"MDK8.1")
 || rpm_exists(rpm:"xchat-", release:"MDK8.2") )
{
 set_kb_item(name:"CVE-2002-0382", value:TRUE);
}
