#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16287);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1184");
 
 name["english"] = "Fedora Core 3 2005-092: enscript";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-092 (enscript).

GNU enscript is a free replacement for Adobe's Enscript
program. Enscript converts ASCII files to PostScript(TM) and spools
generated PostScript output to the specified printer or saves it to a
file. Enscript can be extended to handle different output media and
includes many options for customizing printouts.

Update Information:

This update fixes a regression introduced by the last update.



Solution : http://www.fedoranews.org/blog/index.php?p=340
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the enscript package";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "Fedora Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"enscript-1.6.1-28.0.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"enscript-debuginfo-1.6.1-28.0.3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"enscript-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-1184", value:TRUE);
}
