#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(19721);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0688", "CVE-2004-0914");
 
 name["english"] = "Fedora Core 3 2005-815: lesstif";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-815 (lesstif).

LessTif is a free replacement for OSF/Motif(R), which provides a full
set of widgets for application development (menus, text entry areas,
scrolling windows, etc.). LessTif is source compatible with
OSF/Motif(R) 1.2. The widget set code is the primary focus of
development. If you are installing lesstif, you also need to install
lesstif-clients.


* Fri May  6 2005 Thomas Woerner <twoerner redhat com> 0.93-36-6.FC3.2
- fixed possible libXpm overflows (#151640)
- allow to write XPM files with absolute path names again (#140815)

* Fri Nov 26 2004 Thomas Woerner <twoerner redhat com> 0.93.36-6.FC3.1
- fixed CVE-2004-0687 (integer overflows) and CVE-2004-0688 (stack overflows)
in embedded Xpm library (#135080)
- latest Xpm patches: CVE-2004-0914 (#135081)




Solution : Get the newest Fedora Updates
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the lesstif package";
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
if ( rpm_check( reference:"lesstif-0.93.36-6.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"lesstif-devel-0.93.36-6.FC3.2", release:"FC3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"lesstif-", release:"FC3") )
{
 set_kb_item(name:"CVE-2004-0688", value:TRUE);
 set_kb_item(name:"CVE-2004-0914", value:TRUE);
}
