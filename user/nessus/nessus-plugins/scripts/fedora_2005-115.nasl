#
# (C) Tenable Network Security
#
# This plugin text is was extracted from the Fedora Security Advisory
#


if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(16349);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2005-0100");
 
 name["english"] = "Fedora Core 2 2005-115: emacs";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is missing the patch for the advisory FEDORA-2005-115 (emacs).

Emacs is a powerful, customizable, self-documenting, modeless text
editor. Emacs contains special code editing features, a scripting
language (elisp), and the capability to read mail, news, and more
without leaving the editor.

Update Information:

This update fixes the CVE-2005-0100 movemail vulnerability
and backports current bug fixes.



Solution : http://www.fedoranews.org/blog/index.php?p=379
Risk factor : High";



 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the emacs package";
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
if ( rpm_check( reference:"emacs-21.3-21.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-nox-21.3-21.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-common-21.3-21.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-el-21.3-21.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-leim-21.3-21.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"emacs-debuginfo-21.3-21.FC2", release:"FC2") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_exists(rpm:"emacs-", release:"FC2") )
{
 set_kb_item(name:"CVE-2005-0100", value:TRUE);
}
