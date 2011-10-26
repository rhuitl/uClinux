#
# (C) Tenable Network Security
# 
#
# Ref: 
#  Date: 26 May 2003 05:53:41 -0000
#  From: Chris R <admin@securityindex.net>
#  To: bugtraq@securityfocus.com
#  Subject: Buffer Overflow? Local Malformed URL attack on D-Link 704p router

if(description)
{
 script_id(11655);
 script_version ("$Revision: 1.7 $");
 
 name["english"] = "D-Link router overflow";
 
 script_name(english:name["english"]);
	     
 desc["english"] = "
The remote host is a D-Link router running a firmware version
older than, or as old as 2.70.

There is a flaw in this version which may allow an attacker
to crash the remote device by sending an overly long
argument to the 'syslog.htm' page.

Solution : None at this time. Filter incoming traffic to this port
Risk factor : High";
		 
	 	     
 script_description(english:desc["english"]);
		    
 
 script_summary(english:"Checks the firmware version of the remote D-Link router");
 script_category(ACT_GATHER_INFO);
 script_family(english:"Denial of Service");
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
 		  francais:"Ce script est Copyright (C) 2002 Tenable Network Security");
		  
 script_require_ports("Services/www", 80);
 script_dependencies("http_version.nasl");
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

if(get_port_state(port))
{
 req = http_get(item:"/syslog.htm", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( "DI-704P" >< res )
 {
   vers = egrep(pattern:"^<TR><TD><HR>WAN Type:.*</BR>", string:res);
   if( vers == NULL ) exit(0);
   
   if(ereg(pattern:".*V(1\.|2\.([0-6][0-9]|70))", string:vers))security_hole(port);
 }
}
