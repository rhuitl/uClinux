#
#  This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
#  based on work from
#  (C) Tenable Network Security
#
#  This script is released under the GNU GPLv2

if(description)
{
 script_id(14256);
 script_cve_id("CVE-2004-1439");
 script_bugtraq_id(10834);
 if ( defined_func("script_xref") ) 
	script_xref(name:"OSVDB", value:"8273");
 
 name["english"] = "BlackJumboDog FTP server multiple command overflow";

script_version("$Revision: 1.7 $");

 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is running BlackJumboDog FTP server.

This FTP server fails to properly check the length of parameters 
in multiple FTP commands, most significant of which is USER, 
resulting in a stack overflow. 

With a specially crafted request, an attacker can execute arbitrary code 
resulting in a loss of integrity, and/or availability.

Solution : Upgrade to version 3.6.2 or newer

Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the version of BlackJumboDog";

 script_summary(english:summary["english"]);
 
 script_category(ACT_MIXED_ATTACK);

 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "FTP";
 script_family(english:family["english"]);
 
 script_dependencies("find_service2.nasl");
 script_require_ports(21, "Services/ftp");
 exit(0);
}

include("ftp_func.inc");
port = get_kb_item("Services/ftp");
if ( ! port ) port = 21;
if ( ! get_port_state(port) ) exit(0);
banner = get_ftp_banner(port:port);
if ( ! banner ) exit(0);
	
#220 FTP ( BlackJumboDog(-RAS) Version 3.6.1 ) ready
#220 FTP ( BlackJumboDog Version 3.6.1 ) ready

if( "BlackJumboDog" >< banner ) 
{
  if (safe_checks())
  {
	if ( egrep(pattern:"^220 .*BlackJumboDog.* Version 3\.([0-5]\.[0-9]+|6\.[01]([^0-9]|$))", string:banner ) )
	security_hole(port);
  }
  else
  {
       req1 = string("USER ", crap(300), "\r\n");
       soc=open_sock_tcp(port);
 	if ( ! soc ) exit(0);
       send(socket:soc, data:req1);    
       close(soc);
       sleep(1);
       soc2 = open_sock_tcp(port);
	if (! soc2 || ! ftp_recv_line(socket:soc))
       {
	  security_hole(port);
	}
	else close(soc2);
	exit(0);
  }
}
