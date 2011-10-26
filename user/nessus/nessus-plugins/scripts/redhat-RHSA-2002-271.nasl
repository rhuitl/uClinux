#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12338);
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2002-1320");

 name["english"] = "RHSA-2002-271: pine";
 
 script_name(english:name["english"]);
 
 desc["english"] = '

  A vulnerability in Pine version 4.44 and earlier releases can cause
  Pine to crash when sent a carefully crafted email.

  [Updated 06 Feb 2003]
  Added fixed packages for Advanced Workstation 2.1

  Pine, developed at the University of Washington, is a tool for reading,
  sending, and managing electronic messages (including mail and news).

  A security problem was found in versions of Pine 4.44 and earlier. In these
  verions, Pine does not allocate enough memory for the parsing and escaping
  of the "From" header, allowing a carefully crafted email to cause a
  buffer overflow on the heap. This will result in Pine crashing.

  All users of Pine on Red Hat Linux Advanced Server are advised to
  update to these errata packages containing a patch to version 4.44
  of Pine that fixes this vulnerability.




Solution : http://rhn.redhat.com/errata/RHSA-2002-271.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the pine packages";
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
if ( rpm_check( reference:"pine-4.44-7.21AS.0", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"pine-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2002-1320", value:TRUE);
}

set_kb_item(name:"RHSA-2002-271", value:TRUE);
