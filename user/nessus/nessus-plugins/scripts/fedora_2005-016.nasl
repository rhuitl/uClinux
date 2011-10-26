#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16268);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1184", "CVE-2004-1185", "CVE-2004-1186");
 
 name["english"] = "Fedora Core 3 2005-016: enscript";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-016 (enscript).

GNU enscript is a free replacement for Adobe's Enscript
program. Enscript converts ASCII files to PostScript(TM) and spools
generated PostScript output to the specified printer or saves it to a
file. Enscript can be extended to handle different output media and
includes many options for customizing printouts.

Update Information:

Erik Sjölund has discovered several security relevant problems in
enscript, a program to converts ASCII text to Postscript and other
formats. The Common Vulnerabilities and Exposures project identifies
the following vulnerabilities:

CVE-2004-1184

Unsanitised input can caues the execution of arbitrary commands
via EPSF pipe support. This has been disabled, also upstream.

CVE-2004-1185

Due to missing sanitising of filenames it is possible that a
specially crafted filename can cause arbitrary commands to be
executed.

CVE-2004-1186

Multiple buffer overflows can cause the program to crash.



Solution : http://www.fedoranews.org/blog/index.php?p=326
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
if ( rpm_check( reference:"enscript-1.6.1-28.0.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"enscript-debuginfo-1.6.1-28.0.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"enscript-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-1184", value:TRUE);
 set_kb_item(name:"CVE-2004-1185", value:TRUE);
 set_kb_item(name:"CVE-2004-1186", value:TRUE);
}
