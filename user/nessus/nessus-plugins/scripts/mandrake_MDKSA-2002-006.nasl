#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:006
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13914);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:006: xchat";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:006 (xchat).


zen-parse discovered a problem in versions 1.4.2 and 1.4.3 of xchat that could
allow a malicious user to send commands to the IRC server they are on which
would take advantage of the CTCP PING reply handler in xchat. This could be used
for denial of service, channel takeovers, and other similar attacks. The problem
exists in 1.6 and 1.8 versions, however it is controlled by the 'percascii'
variable which defaults to 0. It 'percascii' is set to 1, the problem is
exploitable. This vulnerability has been fixed upstream in version 1.8.7.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:006
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
if ( rpm_check( reference:"xchat-1.8.7-1.3mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-1.8.7-1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-1.8.7-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"xchat-1.8.7-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
