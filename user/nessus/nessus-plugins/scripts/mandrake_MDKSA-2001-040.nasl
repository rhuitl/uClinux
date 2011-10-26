#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:040-1
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13860);
 script_version ("$Revision: 1.4 $");
 
 name["english"] = "MDKSA-2001:040-1: samba";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:040-1 (samba).


A vulnerability found by Marcus Meissner exists in Samba where it was not
creating temporary files safely which could allow local users to overwrite files
that they may not have access to. This happens when a remote user queried a
printer queue and samba would create a temporary file in which the queue's data
was written. Because Samba created the file insecurely and used a predictable
filename, a local attacker could cause Samba to overwrite files that the
attacker did not have access to. As well, the smbclient 'more' and 'mput'
commands also created temporary files insecurely.
The vulnerability is present in Samba 2.0.7 and lower. 2.0.8 and 2.2.0 correct
this behaviour.
Update:
The Samba 2.0.8 release did not entirely fix the temporary file issues in
previous versions. The Samba team released 2.0.9 recently which does fix these
problems completely. As well, the 8.0 packages will now not attempt to use
/root/tmp as the temporary directory, but /var/tmp.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:040-1
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the samba package";
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
if ( rpm_check( reference:"samba-2.0.9-1.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.0.9-1.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.0.9-1.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.0.9-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.0.9-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.0.9-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-2.0.9-1.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-client-2.0.9-1.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"samba-common-2.0.9-1.3mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
