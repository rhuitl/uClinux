#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2002:024
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13932);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2002:024: rsync";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2002:024 (rsync).


Ethan Benson discovered a bug in rsync where the supplementary groups that the
rsync daemon runs as (such as root) would not be removed from the server process
after changing to the specified unprivileged uid and gid. This seems only
serious if rsync is called using 'rsync --daemon' from the command line where it
will inherit the group of the user starting the server (usually root). Note
that, by default, Mandrake Linux uses xinetd to handle connections to the rsync
daemon. This was fixed upstream in version 2.5.3, as well as the previously
noted zlib fixes (see MDKSA-2002:023). The authors released 2.5.4 with some
additional zlib fixes, and all users are encouraged to upgrade to this new
version of rsync.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2002:024
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
if ( rpm_check( reference:"rsync-2.5.4-1.2mdk", release:"MDK7.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.4-1.1mdk", release:"MDK7.2", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.4-1.1mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"rsync-2.5.4-1.1mdk", release:"MDK8.1", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
