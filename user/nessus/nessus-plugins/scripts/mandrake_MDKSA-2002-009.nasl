#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:009
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13917);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:009: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:009 (rsync).


Sebastian Krahmer of the SuSE Security Team performed an audit on the rsync tool
and discovered that in several places signed and unsigned numbers were mixed,
with the end result being insecure code. These flaws could be abused by remote
users to write 0 bytes into rsync's memory and trick rsync into executing
arbitrary code on the server.
It is recommended that all Mandrake Linux users update rsync immediately. As
well, rsync server administrators should seriously consider making use of the
'use chroot', 'read only', and 'uid' options as these can significantly reduce
the impact that security problems in rsync (or elsewhere) have on the server.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:009
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
if ( rpm_check( reference:"rsync-2.4.6-3.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.4.6-3.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.4.6-3.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.4.6-3.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
