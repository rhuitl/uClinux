#
# (C) Tenable Network Security
#
#
# The text of this plugin is (C) Red Hat Inc.

if ( ! defined_func("bn_random") ) exit(0);
if(description)
{
 script_id(15943);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2005-t-0015");
 script_version ("$Revision: 1.3 $");
 script_cve_id("CVE-2004-0687", "CVE-2004-0688", "CVE-2004-0914");

 name["english"] = "RHSA-2004-537: openmotif";
 
 script_name(english:name["english"]);
 
 desc["english"] = '
                                                                                    
  Updated openmotif packages that fix flaws in the Xpm image library are now        
  available.                                                                        
                                                                                    
  OpenMotif provides libraries which implement the Motif industry standard          
  graphical user interface.                                                         
                                                                                    
  During a source code audit, Chris Evans and others discovered several stack       
  overflow flaws and an integer overflow flaw in the libXpm library used to         
  decode XPM (X PixMap) images. A vulnerable version of this library was            
  found within OpenMotif. An attacker could create a carefully crafted              
  XPM file which would cause an application to crash or potentially execute         
  arbitrary code if opened by a victim. The Common Vulnerabilities and              
  Exposures project (cve.mitre.org) has assigned the names                          
  CVE-2004-0687, CVE-2004-0688, and CVE-2004-0914 to these issues.                  
                                                                                    
  Users of OpenMotif are advised to upgrade to these erratum packages, which        
  contain backported security patches to the embedded libXpm library.               
                                                                                    
                                                                                    


Solution : http://rhn.redhat.com/errata/RHSA-2004-537.html
Risk factor : High';

 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of the openmotif packages";
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
if ( rpm_check( reference:"openmotif-2.1.30-13.21AS.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.1.30-13.21AS.4", release:"RHEL2.1") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-2.2.3-4.RHEL3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif-devel-2.2.3-4.RHEL3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}
if ( rpm_check( reference:"openmotif21-2.1.30-9.RHEL3.4", release:"RHEL3") )
{
 security_hole(0);
 exit(0);
}

if ( rpm_exists(rpm:"openmotif-", release:"RHEL2.1") )
{
 set_kb_item(name:"CVE-2004-0687", value:TRUE);
 set_kb_item(name:"CVE-2004-0688", value:TRUE);
 set_kb_item(name:"CVE-2004-0914", value:TRUE);
}
if ( rpm_exists(rpm:"openmotif-", release:"RHEL3") )
{
 set_kb_item(name:"CVE-2004-0687", value:TRUE);
 set_kb_item(name:"CVE-2004-0688", value:TRUE);
 set_kb_item(name:"CVE-2004-0914", value:TRUE);
}

set_kb_item(name:"RHSA-2004-537", value:TRUE);
