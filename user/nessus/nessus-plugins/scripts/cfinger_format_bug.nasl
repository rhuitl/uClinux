#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#
# 

if(description)
{
 script_id(10652);
 script_bugtraq_id(2576, 651);
 script_cve_id("CVE-1999-0243", "CVE-1999-0708", "CVE-2001-0609");
 script_version ("$Revision: 1.13 $");
 name["english"] = "cfingerd format string attack";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote cfingerd daemon, according to its version number,
is vulnerable to a format string attack that lets anyone
execute arbitrary commands on this host.

Solution : upgrade to version 1.4.4
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "cfinger version";
 summary["francais"] = "cfinger version";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Finger abuses";
 family["francais"] = "Abus de finger";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", 
 		     "cfinger_version.nasl");
 script_require_keys("cfingerd/version");
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/finger");
if(!port)port = 79;

version = get_kb_item("cfingerd/version");
if(version)
{
 if(ereg(pattern:"[0-1]\.(([0-3]\.[0-9]*)|(4\.[0-3]))",
 	string:version))security_hole(port);
}
