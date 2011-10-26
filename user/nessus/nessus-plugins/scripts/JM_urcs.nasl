#
# This script was written by J.Mlødzianøwski <jøseph[at]rapter.net>
# 
# 

if(description)
{
 script_id(15405);
 script_version("$Revision: 1.6 $");
 name["english"] = "URCS Server Detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
This host appears to be running URCS Server. Unmanarc Remote Control Server 
can be used/installed silent as a 'backdoor' which may allow an intruder to 
gain remote access to files on the remote system. If this program was not 
installed for remote management then it means the remote host has been
compromised. 

An attacker may use it to steal files, passwords, or redirect ports on the
remote system to launch other attacks.

Solution : see http://www.rapter.net/jm5.htm 
See also : 
 - http://urcs.unmanarc.com
 - http://securityresponse.symantec.com/avcenter/venc/data/backdoor.urcs.html
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines the presence of the URCS Server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright(C) 9/2004 J.Mlodzianowski");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencie("find_service2.nasl");
 exit(0);
}

#
# The code starts here:
#

include("misc_func.inc");
include('global_settings.inc');

if ( ! thorough_tests  )
{
 port = 3360;
}
else
{
 port = get_unknown_svc(3360);
 if ( ! port ) exit(0);
}
# Default port for URCS Server is 3360
# Default port for URCS Client is 1980
 if (get_port_state(port))
{
 soc= open_sock_tcp(port);
 if(soc)
{
 send(socket:soc, data:'iux');
 r = recv(socket:soc, length:817);
 if ( "$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$" >< r ) 
	security_hole(port);
 close(soc);
 }
} 
