#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>

# See the Nessus Scripts License for details
#

if(description)
{
 script_id(12266);
 script_version ("$Revision: 1.2 $");
 name["english"] = "Dabber worm detection";
 script_name(english:name["english"]);
 
 desc["english"] = "
W32.Dabber propagates by exploiting a vulnerability in the FTP server 
component of W32.Sasser.Worm and its variants.
It installs a backdoor on infected hosts and tries to listen on port 9898.
If the attempt fails, W32Dabber.A tries to listen on ports 9899 through 9999 
in sequence until it finds an open port. 

See also :
http://securityresponse.symantec.com/avcenter/venc/data/w32.dabber.b.html
http://www.microsoft.com/technet/security/bulletin/MS04-011.mspx

Solution: 
- Disable access to port 445 and Dabber remote shell by using a firewall
- Apply Microsoft MS04-011 patch
- Update your virus definitions

Risk factor : High";
 
 script_description(english:desc["english"]);
 summary["english"] = "Dabber worm detection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004 David Maciejak");
 family["english"] = "Backdoors";
 script_family(english:family["english"]);
 script_dependencies("find_service2.nasl");
 script_require_ports(5554);
 exit(0);
}

#
# The script code starts here
#
sasser_port = 5554;    
dabber_ports = make_list();

for ( port = 9898 ; port <= 9999 ; port ++ ) 
{
	dabber_ports = make_list(dabber_ports, port);
}

if (get_port_state(sasser_port))
{
	if (open_sock_tcp(sasser_port)) 
	{		
		foreach port (dabber_ports)
		{
			if (get_port_state(port)) 
			{	
				soc=open_sock_tcp(port);
				if (soc)
				{
					buf = string("C");
					send(socket:soc, data:buf);
					data_root = recv(socket:soc, length:2048);
				        close(soc);

					if(data_root)
  					{
						security_hole(port);
					}
				}
			}
		}
	}
}
exit(0);
