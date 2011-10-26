#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2004:041
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(14140);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2004:041: proftpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2004:041 (proftpd).


A portability workaround that was applied in version 1.2.9 of the ProFTPD FTP
server caused CIDR based ACL entries in 'Allow' and 'Deny' directives to act
like an 'AllowAll' directive. This granted FTP clients access to files and
directories that the server configuration may have been explicitly denying.
This problem only exists in version 1.2.9 and has been fixed upstream. A patch
has been applied to correct the problem.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2004:041
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
if ( rpm_check( reference:"proftpd-1.2.9-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-anonymous-1.2.9-3.1.100mdk", release:"MDK10.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
