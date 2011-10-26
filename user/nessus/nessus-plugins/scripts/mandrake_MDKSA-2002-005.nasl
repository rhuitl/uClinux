#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:005
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13913);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:005: proftpd";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:005 (proftpd).


Matthew S. Hallacy discovered that ProFTPD was not forward resolving
reverse-resolved hostnames. A remote attacker could exploit this to bypass
ProFTPD access controls or have false information logged. Frank Denis discovered
that a remote attacker could send malicious commands to the ProFTPD server and
it would force the process to consume all CPU and memory resources available to
it. This DoS vulnerability could bring the server down with repeated attacks.
Finally, Mattias found a segmentation fault problem that is considered by the
developers to be unexploitable.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:005
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
if ( rpm_check( reference:"proftpd-1.2.5-0.rc1.1.2mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.2.5-0.rc1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"proftpd-1.2.5-0.rc1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
