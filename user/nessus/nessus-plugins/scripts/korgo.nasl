#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# See the Nessus Scripts License for details
#
# This script is released under the GNU GPLv2



if(description)
{
 script_id(12252);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Korgo worm detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host is probably infected with Korgo worm.
It propagates by exploiting the LSASS vulnerability on TCP port 445 
(as described in Microsoft Security Bulletin MS04-011)
and opens a backdoor on TCP ports 113 and 3067.

See also :
http://securityresponse.symantec.com/avcenter/venc/data/w32.korgo.c.html
http://www.microsoft.com/technet/security/bulletin/MS04-011.mspx

Solution: 
- Disable access to port 445 by using a firewall
- Apply Microsoft MS04-011 patch.

Risk factor : High";
 
 script_description(english:desc["english"]);
 summary["english"] = "Korgo worm detection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes");
 script_require_ports(113, 3067);
 exit(0);
}

#
# The script code starts here
#
ports[0] =  3067;           
ports[1] =  113;

if (get_port_state(ports[0]))
{
	soc1 = open_sock_tcp(ports[0]);
	if (soc1) 
	{	
		if (get_port_state(ports[1]))
		{
			soc2 = open_sock_tcp(ports[1]);
			if (soc1 && soc2)
			{	
				close(soc1);
				close(soc2);
				security_hole(ports[0]);
			}
		}
	}
}
exit(0);
