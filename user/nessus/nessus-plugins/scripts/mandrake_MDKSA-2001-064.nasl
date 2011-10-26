#
# (C) Tenable Network Security
#
# This plugin text was extracted from Mandrake Linux Security Advisory MDKSA-2001:064
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13879);
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "MDKSA-2001:064: tripwire";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory MDKSA-2001:064 (tripwire).


Jarno Juuskonen reported that a temporary file vulnerability exists in versions
of Tripwire prior to 2.3.1-2. Because Tripwire opens/creates temporary files in
/tmp without the O_EXCL flag during filesystem scanning and database updating, a
malicious user could execute a symlink attack against the temporary files. This
new version has all but one unsafe temporary file open fixed. It can still be
used safely when using the new TEMPDIRECTORY configuration option, which is now
set to /root/tmp.


Solution : http://wwwnew.mandriva.com/security/advisories?name=MDKSA-2001:064
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the tripwire package";
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
if ( rpm_check( reference:"tripwire-2.3.1.2-2.2mdk", release:"MDK8.0", yank:"mdk") )
{
 security_hole(0);
 exit(0);
}
