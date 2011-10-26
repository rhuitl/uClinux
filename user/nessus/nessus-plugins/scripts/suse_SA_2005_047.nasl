#
# (C) Tenable Network Security
#
# This plugin text was extracted from SuSE Security Advisory SUSE-SA:2005:047
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19926);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0033");
 script_version ("$Revision: 1.3 $");
 
 name["english"] = "SUSE-SA:2005:047: acroread";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory SUSE-SA:2005:047 (acroread).


A buffer overflow was found in the core application plug-in for the
Adobe Reader, that allows attackers to cause a denial of service
(crash) and possibly execute arbitrary code via unknown vectors.

This is tracked by the Mitre CVE ID CVE-2005-2470.

Note that for SUSE Linux Enterprise Server 8 and SUSE Linux Desktop 1
Acrobat Reader support was already discontinued by an earlier
announcement.


Solution : http://www.suse.de/security/advisories/2005_47_acroread.html
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the acroread package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "SuSE Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/SuSE/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"acroread-7.0.1-3", release:"SUSE9.0") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.1-2.2", release:"SUSE9.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.1-2.1", release:"SUSE9.2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"acroread-7.0.1-2.1", release:"SUSE9.3") )
{
 security_hole(0);
 exit(0);
}
