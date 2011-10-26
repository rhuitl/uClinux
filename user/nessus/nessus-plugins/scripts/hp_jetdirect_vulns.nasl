#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Script License for details
#


if(description)
{
 script_id(11396);
 script_bugtraq_id(7070);
 script_version("$Revision: 1.1 $");


 name["english"] = "hp jetdirect vulnerabilities";

 script_name(english:name["english"]);

 desc["english"] = "
The remote hp jetdirect is, according to its version number,
vulnerable to a vulnerability which may allow an attacker to
gain unauthorized access on this printer, or crash it.


Solution : Upgrade to Firmware Q.24.09
See also : http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c00001902
Risk factor : High";
 script_description(english:desc["english"]);

 summary["english"] = "Uses SNMP to determine if a flaw is present";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is (C) 2003 Renaud Deraison");

 script_family(english:"Misc.");

 script_dependencie("snmp_sysDesc.nasl");
 script_require_keys("SNMP/community",
			  "SNMP/sysDesc");
 
 exit(0);
}



os = get_kb_item("SNMP/sysDesc"); if(!os)exit(0);
if(egrep(pattern:"JETDIRECT.*Q\.24\.06", string:os, icase:TRUE))
  	security_hole(0);


