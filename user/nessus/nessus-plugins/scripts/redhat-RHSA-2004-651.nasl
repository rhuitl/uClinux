#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15947);
 script_version ("$Revision: 1.2 $");
 script_cve_id("CVE-2004-1025", "CVE-2004-1026");

 name["english"] = "RHSA-2004-651: imlib";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
                                                                               
  Updated imlib packages that fix several integer and buffer overflows are     
  now available.                                                               
                                                                               
  The imlib packages contain an image loading and rendering library.           
                                                                               
  Pavel Kankovsky discovered several heap overflow flaws that were found in    
  the imlib image handler. An attacker could create a carefully crafted image  
  file in such a way that it could cause an application linked with imlib to   
  execute arbitrary code when the file was opened by a victim. The Common      
  Vulnerabilities and Exposures project (cve.mitre.org) has assigned the name  
  CVE-2004-1025 to this issue.                                                 
                                                                               
  Additionally, Pavel discovered several integer overflow flaws that were      
  found in the imlib image handler. An attacker could create a carefully       
  crafted image file in such a way that it could cause an application linked   
  with imlib to execute arbitrary code or crash when the file was opened by a  
  victim. The Common Vulnerabilities and Exposures project (cve.mitre.org)     
  has assigned the name CVE-2004-1026 to this issue.                           
                                                                               
  Users of imlib should update to these updated packages, which contain        
  backported patches and are not vulnerable to this issue.                     
                                                                               
                                                                               


Solution : http://rhn.redhat.com/errata/RHSA-2004-651.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the imlib packages";
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
if ( rpm_check( reference:"imlib-1.9.13-4.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-cfgeditor-1.9.13-4.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-4.3", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-1.9.13-13.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"imlib-devel-1.9.13-13.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"imlib-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-1025", value:TRUE);
 set_kb_item(name:"CVE-2004-1026", value:TRUE);
}
if ( rpm_exists(rpm:"imlib-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-1025", value:TRUE);
 set_kb_item(name:"CVE-2004-1026", value:TRUE);
}

set_kb_item(name:"RHSA-2004-651", value:TRUE);
