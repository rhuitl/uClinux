#
# (C) Tenable Network Security
#
#
if ( ! defined_func("bn_random") ) exit(0);


if(description)
{
 script_id(14311);
 script_bugtraq_id(10259);
 script_version ("$Revision: 1.6 $");
 script_cve_id("CVE-2004-0422");
			
 name["english"] = "RHSA-2004-344: semi";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running a vulnerable version of SEMI.

Semi is a MIME library for GNU Emacs and XEmacs used by the wl mail package.

This version of SEMI is vulnerable to a bug wherein temporary files
are created in a manner which would allow local users to overwrite 
and/or read potentially confidential data.  An attacker, exploiting
this flaw, would need local access to the machine and the ability
to create or modify files as they are being created.

Solution : http://rhn.redhat.com/errata/RHSA-2004-344.html

Risk factor : Medium";

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

if ( rpm_check( reference:"semi-1.14.3-8.72.EL.1", yank:"EL", prefix:"semi-", release:"RHEL2.1") ) 
	security_warning(0);


