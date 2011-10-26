#
# (C) Tenable Network Security
#
#

if(description)
{
 script_id(12521);
 if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0027");
 script_bugtraq_id(10904, 10406, 10401, 10400);
 script_version ("$Revision: 1.12 $");
 name["english"] = "MacOS X Version";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
This script makes sure that the remote host is running an up-to-date
version of the MacOS X operating system. It also fills the Nessus
knowledge base with the list of CVE IDs that each release of the
operating system fixes.";


 script_description(english:desc["english"]);
 
 summary["english"] = "Check for the version of MacOS X";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "MacOS X Local Security Checks";
 script_family(english:family["english"]);
 
 if ( defined_func("bn_random") )
 	script_dependencies("os_fingerprint.nasl", "ssh_get_info.nasl");
 else
 	script_dependencies("os_fingerprint.nasl");
 script_require_keys("Host/OS/icmp");
 exit(0);
}


os = get_kb_item("Host/MacOSX/Version");
if ( ! os ) os = get_kb_item("Host/OS/icmp");

if ( ! os ) exit(0);


if ( os && "Mac OS X" >< os )
{
 if ( ereg(pattern:"Mac OS X 10\.1\.", string:os ))
 {
  report = "
The remote host is running Mac OS X 10.1. This version is not supported
by Apple any more, you should upgrade the remote host to the latest version
of Mac OS X.";
  if ( ereg(pattern:"Mac OS X 10\.1\.[0-4]", string:os ))
  {
   report += "
In addition to this, the remote host should at least be upgraded to 
MacOS 10.1.5 using 'softwareupdate', as it's the last supported version 
of the system";
  }
  security_hole(port:0, data:report);
 }

 if ( ereg(pattern:"Mac OS X 10\.2\.", string:os ))
 {
  report = "
The remote host is running Mac OS X 10.2. This version is not supported
by Apple any more, you should upgrade the remote host to the latest version
of Mac OS X.";
  if ( ereg(pattern:"Mac OS X 10\.2\.[0-7]", string:os ))
  {
   report += "
In addition to this, the remote host should at least be upgraded to 
MacOS 10.2.8 using 'softwareupdate', as it's the last supported version 
of the system";
  }

  security_hole(port:0, data:report);
 }

 if ( ereg(pattern:"Mac OS X 10\.([3-9]|2\.8)", string:os ) )
 {
  set_kb_item(name:"CVE-2003-0542", value:TRUE);
  set_kb_item(name:"CVE-2003-0543", value:TRUE);
  set_kb_item(name:"CVE-2003-0544", value:TRUE);
  set_kb_item(name:"CVE-2003-0545", value:TRUE);
 }



 

 if ( ereg(pattern:"Mac OS X 10\.3\.[0-8]", string:os ))
 {
  report = "
The remote host is running a version of Mac OS X 10.3 which is older
than version 10.3.9.

Apple's newest security updates require Mac OS X 10.3.9 to be applied
properly. The remote host should be upgraded to this version as soon 
as possible";

  security_hole(port:0, data:report);
 }

 if ( ereg(pattern:"Mac OS X 10\.(3\.[3-9]|[4-9])", string:os ))
 {
    set_kb_item(name:"CVE-2004-0174", value:TRUE);
    set_kb_item(name:"CVE-2003-0020", value:TRUE);
 }


 if ( ereg(pattern:"Mac OS X 10\.(3\.[4-9]|[4-9])", string:os))
 {
   set_kb_item(name:"CVE-2004-0174", value:TRUE);
   set_kb_item(name:"CVE-2003-0020", value:TRUE);
   set_kb_item(name:"CVE-2004-0079", value:TRUE);
   set_kb_item(name:"CVE-2004-0081", value:TRUE);
   set_kb_item(name:"CVE-2004-0112", value:TRUE);
 }

 if ( ereg(pattern:"Mac OS X 10\.(3\.[5-9]|[4-9])", string:os))
 {
   set_kb_item(name:"CVE-2002-1363", value:TRUE);
   set_kb_item(name:"CVE-2004-0421", value:TRUE);
   set_kb_item(name:"CVE-2004-0597", value:TRUE);
   set_kb_item(name:"CVE-2004-0598", value:TRUE);
   set_kb_item(name:"CVE-2004-0599", value:TRUE);
   set_kb_item(name:"CVE-2004-0743", value:TRUE);
   set_kb_item(name:"CVE-2004-0744", value:TRUE);
 }
 if ( ereg(pattern:"Mac OS X 10\.(3\.[7-9]|[4-9])", string:os))
 {
   set_kb_item(name:"CVE-2004-1082", value:TRUE);
   set_kb_item(name:"CVE-2003-0020", value:TRUE);
   set_kb_item(name:"CVE-2003-0987", value:TRUE);
   set_kb_item(name:"CVE-2004-0174", value:TRUE);
   set_kb_item(name:"CVE-2004-0488", value:TRUE);
   set_kb_item(name:"CVE-2004-0492", value:TRUE);
   set_kb_item(name:"CVE-2004-0885", value:TRUE);
   set_kb_item(name:"CVE-2004-0940", value:TRUE);
   set_kb_item(name:"CVE-2004-1083", value:TRUE);
   set_kb_item(name:"CVE-2004-1084", value:TRUE);
   set_kb_item(name:"CVE-2004-0747", value:TRUE);
   set_kb_item(name:"CVE-2004-0786", value:TRUE);
   set_kb_item(name:"CVE-2004-0751", value:TRUE);
   set_kb_item(name:"CVE-2004-0748", value:TRUE);
   set_kb_item(name:"CVE-2004-1081", value:TRUE);
   set_kb_item(name:"CVE-2004-0803", value:TRUE);
   set_kb_item(name:"CVE-2004-0804", value:TRUE);
   set_kb_item(name:"CVE-2004-0886", value:TRUE);
   set_kb_item(name:"CVE-2004-1089", value:TRUE);
   set_kb_item(name:"CVE-2004-1085", value:TRUE);
   set_kb_item(name:"CVE-2004-0642", value:TRUE);
   set_kb_item(name:"CVE-2004-0643", value:TRUE);
   set_kb_item(name:"CVE-2004-0644", value:TRUE);
   set_kb_item(name:"CVE-2004-0772", value:TRUE);
   set_kb_item(name:"CVE-2004-1088", value:TRUE);
   set_kb_item(name:"CVE-2004-1086", value:TRUE);
   set_kb_item(name:"CVE-2004-1123", value:TRUE);
   set_kb_item(name:"CVE-2004-1121", value:TRUE);
   set_kb_item(name:"CVE-2004-1122", value:TRUE);
   set_kb_item(name:"CVE-2004-1087", value:TRUE);
 }
}
