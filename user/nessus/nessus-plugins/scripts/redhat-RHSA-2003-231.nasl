#
# (C) Tenable Network Security
#
#

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(12408);
 script_bugtraq_id(8115);
 script_version ("$Revision: 1.4 $");
 script_cve_id("CVE-2003-0440");

 name["english"] = "RHSA-2003-231: semi";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host has an old version of the semi package installed.

semi is a MIME library for GNU Emacs and XEmacs, which is used by
the wl mail package.

There is a vulnerability in version 1.14.3 and earlier of this
software which may allow an attacker to overwrite arbitrary files
on the remote system with the privileges of the user reading his
mail with wl.

To exploit this flaw, an attacker would need to send a carefully
crafted MIME encoded email to a victim on the remote host, and
wait for him to open it using wl.

Solution : https://rhn.redhat.com/errata/RHSA-2003-231.html
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the semi package";
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


if ( rpm_check( reference:"semi-1.14.3-8.72.EL",yank:"EL", release:"RHEL2.1") )
	security_hole(0);
