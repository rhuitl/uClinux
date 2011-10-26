#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2003:018
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(13788);
 script_version ("$Revision: 1.5 $");
 script_cve_id("CVE-2003-0143");
 
 name["english"] = "SUSE-SA:2003:018: qpopper";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2003:018 (qpopper).


The Post-Office-Protocol- (POP-) Server qpopper (version 4) was
vulnerable to a buffer overflow. The buffer overflow occurs after
authentication has taken place. Therefore pop-users with a valid
account can execute arbitrary code on the system running qpopper.
Depending on the setup, the malicious code is run with higher privileges.

There is no temporary fix known, please update your system.

Please download the update package for your distribution and verify its
integrity by the methods listed in section 3) of this announcement.
Then, install the package using the command 'rpm -Fhv file.rpm' to apply
the update.

Solution : http://www.suse.de/security/2003_018_qpopper.html
Risk factor : Medium";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the qpopper package";
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
if ( rpm_check( reference:"qpopper-4.0.4-133", release:"SUSE8.1") )
{
 security_warning(0);
 exit(0);
}
if ( rpm_check( reference:"qpopper-4.0.3-178", release:"SUSE8.0") )
{
 security_warning(0);
 exit(0);
}
if (rpm_exists(rpm:"qpopper-", release:"SUSE8.1")
 || rpm_exists(rpm:"qpopper-", release:"SUSE8.0") )
{
 set_kb_item(name:"CVE-2003-0143", value:TRUE);
}
