#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:001
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13909);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:001: bind";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:001 (bind).


There are some insecure permissions on configuration files and executables with
the bind 9.x packages shipped with Mandrake Linux 8.0 and 8.1. This update
provides stricter permissions by making the /etc/rndc.conf and /etc/rndc.key
files read/write by the named user and by making /sbin/rndc-confgen and
/sbin/rndc read/write/executable only by root.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:001
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the bind package";
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
if ( rpm_check( reference:"bind-9.1.1-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.1.1-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.1.1-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-9.2.0-0.rc3.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-devel-9.2.0-0.rc3.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"bind-utils-9.2.0-0.rc3.2mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
