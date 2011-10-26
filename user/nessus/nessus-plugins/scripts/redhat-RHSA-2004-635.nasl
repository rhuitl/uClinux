#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15945);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-0983");

 name["english"] = "RHSA-2004-635: irb";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
                                                                               
  An updated ruby package that fixes a denial of service issue for the CGI     
  instance is now available.                                                   
                                                                               
  Ruby is an interpreted scripting language for object-oriented programming.   
                                                                               
  A flaw was dicovered in the CGI module of Ruby. If empty data is sent by     
  the POST method to the CGI script which requires MIME type                   
  multipart/form-data, it can get stuck in a loop. A remote attacker could     
  trigger this flaw and cause a denial of service. The Common                  
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name  
  CVE-2004-0983 to this issue.                                                 
                                                                               
  Users are advised to upgrade to this erratum package, which contains a       
  backported patch to cgi.rb.                                                  
                                                                               
                                                                               


Solution : http://rhn.redhat.com/errata/RHSA-2004-635.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the irb packages";
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
if ( rpm_check( reference:"irb-1.6.4-2.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-1.6.4-2.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-devel-1.6.4-2.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-docs-1.6.4-2.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-libs-1.6.4-2.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"ruby-tcltk-1.6.4-2.AS21.1", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"irb-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0983", value:TRUE);
}

set_kb_item(name:"RHSA-2004-635", value:TRUE);
