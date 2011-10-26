#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12472);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0592");

 name["english"] = "RHSA-2004-074: arts";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  Updated kdelibs packages that fix a flaw in cookie path handling are now
  available.

  Konqueror is a file manager and Web browser for the K Desktop Environment
  (KDE).

  Flaws have been found in the cookie path handling between a number of Web
  browsers and servers. The HTTP cookie standard allows a Web server
  supplying a cookie to a client to specify a subset of URLs on the origin
  server to which the cookie applies. Web servers such as Apache do not
  filter returned cookies and assume that the client will only send back
  cookies for requests that fall within the server-supplied subset of URLs.
  However, by supplying URLs that use path traversal (/../) and character
  encoding, it is possible to fool many browsers into sending a cookie to a
  path outside of the originally-specified subset.

  KDE version 3.1.3 and later include a patch to Konquerer that disables the
  sending of cookies to the server if the URL contains such encoded
  traversals. Red Hat Enterprise Linux 2.1 shipped with KDE 2.2.2 and
  is therefore vulnerable to this issue.

  Users of Konquerer are advised to upgrade to these erratum packages, which
  contain a backported patch for this issue.




Solution : http://rhn.redhat.com/errata/RHSA-2004-074.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the arts packages";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Red Hat Local Security Checks";
 script_family(english:family["english"]);
 
 script_dependencies("ssh_get_info.nasl");
 
 script_require_keys("Host/RedHat/rpm-list");
 exit(0);
}

include("rpm.inc");
if ( rpm_check( reference:"arts-2.2.2-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-2.2.2-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-devel-2.2.2-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-2.2.2-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"kdelibs-sound-devel-2.2.2-10", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"arts-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2003-0592", value:TRUE);
}

set_kb_item(name:"RHSA-2004-074", value:TRUE);
