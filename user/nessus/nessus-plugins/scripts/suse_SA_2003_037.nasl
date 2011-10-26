#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:037
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13805);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0720", "CVE-2003-0721");
 
 name["english"] = "SUSE-SA:2003:037: pine";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:037 (pine).


The well known and widely used mail client pine is vulnerable to
a buffer overflow.  The vulnerability exists in the code processing
'message/external-body' type messages. It allows remote attackers
to execute arbitrary commands as the user running pine.
Additionally an integer overflow in the MIME header parsing code
has been fixed.

Since there is no workaround, an update is strongly recommended for
pine users.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_037_pine.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pine package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"pine-4.33-279", release:"SUSE7.2") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.33-280", release:"SUSE7.3") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.44-281", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.44-283", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"pine-4.53-109", release:"SUSE8.2") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"pine-", release:"SUSE7.2")
 || rpm_exists(rpm:"pine-", release:"SUSE7.3")
 || rpm_exists(rpm:"pine-", release:"SUSE8.0")
 || rpm_exists(rpm:"pine-", release:"SUSE8.1")
 || rpm_exists(rpm:"pine-", release:"SUSE8.2") )
{
 set_kb_item(name:"CVE-2003-0720", value:TRUE);
 set_kb_item(name:"CVE-2003-0721", value:TRUE);
}
