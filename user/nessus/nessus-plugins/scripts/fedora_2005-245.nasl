#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19631);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0237", "CVE-2005-0365", "CVE-2005-0396");
 
 name["english"] = "Fedora Core 3 2005-245: kdelibs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-245 (kdelibs).

Libraries for the K Desktop Environment:
KDE Libraries included: kdecore (KDE core library), kdeui (user interface),
kfm (file manager), khtmlw (HTML widget), kio (Input/Output, networking),
kspell (spelling checker), jscript (javascript), kab (addressbook),
kimgio (image manipulation).

* Wed Mar 23 2005 Than Ngo <than redhat com> 6:3.3.1-2.9.FC3
- Applied patch to fix konqueror international domain name spoofing,
CVE-2005-0237, #147405
- get rid of broken AltiVec instructions on ppc

* Wed Mar 2 2005 Than Ngo <than redhat com> 6:3.3.1-2.8.FC3
- Applied patch to fix DCOP DoS, CVE-2005-0396, #150092
thanks KDE security team

* Wed Feb 16 2005 Than Ngo <than redhat com> 6:3.3.1-2.7.FC3
- Applied patch to fix dcopidlng insecure temporary file usage,
CVE-2005-0365, #148823


Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the kdelibs package";
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
if ( rpm_check( reference:"kdelibs-3.3.1-2.9.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-3.3.1-2.9.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-debuginfo-3.3.1-2.9.FC3", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"kdelibs-", release:"FC3") )
{
 set_kb_item(name:"CVE-2005-0237", value:TRUE);
 set_kb_item(name:"CVE-2005-0365", value:TRUE);
 set_kb_item(name:"CVE-2005-0396", value:TRUE);
}
