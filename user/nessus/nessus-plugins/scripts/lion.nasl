#
# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10646);
 script_version ("$Revision: 1.12 $");

 name["english"] = "Lion worm";
 name["francais"] = "Lion worm";
 script_name(english:name["english"], francais:name["francais"]);
 
 desc["english"] = "
This host seems to be infected by the lion worm, because
it has shells running on extra port and a copy of SSH
running on port 33568.

Solution : re-install this system from scratch
See also : http://www.sans.org/y2k/lion.htm
Risk factor : Critical";



 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of Lion";
 summary["francais"] = "Détermine la présence de Lion";
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2001 Renaud Deraison",
		francais:"Ce script est Copyright (C) 2001 Renaud Deraison");
 family["english"] = "Backdoors";
 family["francais"] = "Backdoors";
 script_family(english:family["english"], francais:family["francais"]);
 script_require_ports(60008, 33567, 33568);
 script_require_keys("Settings/ThoroughTests");
 exit(0);
}

#
# The script code starts here
#

include('global_settings.inc');

if ( ! thorough_tests ) exit(0);

function check_shell(port)
{
 soc = open_sock_tcp(port);
 if(!soc)return(0);
 #r = recv(socket:soc, length:4096);
 r = string("id\r\n");
 send(socket:soc, data:r);
 r = recv(socket:soc, length:4096);
 close(soc);
 if("command not found" >< r){
 	security_hole(port);
	return(1);
	}
  if("uid=" >< r){
  	security_hole(port);
	return(1);
	}
 return(0);
}

if(get_port_state(60008))
{
 if(check_shell(port:60008))
  exit(0);
}

if(get_port_state(33567))
{
 if(check_shell(port:33567))
  exit(0);
}

if(get_port_state(33568))
{
 soc = open_sock_tcp(33568);
 if(soc)
 {
  r = recv(socket:soc, length:4096);
  close(soc);
  if(r)
  {
   if("SSH-" >< r)security_hole(33568);
   exit(0);
  }
 }
}
