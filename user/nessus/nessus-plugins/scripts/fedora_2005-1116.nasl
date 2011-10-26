#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(20258);
 script_version ("$Revision: 1.1 $");
 script_cve_id("CAN-2004-0976", "CVE-2004-0976", "CVE-2005-0452", "CVE-2005-3912", "CVE-2005-3962");
 
 name["english"] = "Fedora Core 3 2005-1116: perl";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-1116 (perl).

Perl is a high-level programming language with roots in C, sed, awk
and shell scripting.  Perl is good at handling processes and files,
and is especially good at handling text.  Perl's hallmarks are
practicality and efficiency.  While it is used to do a lot of
different things, Perl's most common applications are system
administration utilities and web programming.  A large proportion of
the CGI scripts on the web are written in Perl.  You need the perl
package installed on your system so that your system can handle Perl
scripts.

Install this package if you want to program in Perl or enable your
system to handle Perl scripts.

Update Information:

Fixes security vulnerabilites:
CVE-2005-3962:
[8]http://marc.theaimsgroup.com/?l=full-disclosure&m=113342788118630&w=2
CVE-2005-3912:
[9]http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-3912
CVE-2005-0452:
[10]http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2005-0452
CVE-2004-0976:
[11]http://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2004-0976


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the perl package";
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
if ( rpm_check( reference:"perl-5.8.5-18.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"perl-suidperl-5.8.5-18.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"perl-", release:"FC3") )
{
 set_kb_item(name:"CAN-2004-0976", value:TRUE);
 set_kb_item(name:"CVE-2004-0976", value:TRUE);
 set_kb_item(name:"CVE-2005-0452", value:TRUE);
 set_kb_item(name:"CVE-2005-3912", value:TRUE);
 set_kb_item(name:"CVE-2005-3962", value:TRUE);
}
