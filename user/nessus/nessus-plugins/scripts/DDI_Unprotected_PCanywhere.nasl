#
# This script was written by H D Moore
#


if(description)
{
 script_id(10798);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0508");
 name["english"] = "Unprotected PC Anywhere Service";
 script_name(english:name["english"]);

 desc["english"] = "
The PC Anywhere service does not require a password to access
the desktop of this system. If this machine is running Windows 95,
98, or ME, gaining full control of the machine is trivial. If
this system is running NT or 2000 and is currently logged out, an
attacker can still spy on and hijack a legitimate user's session when
they login.  

Solution:  
1. Open the PC Anywhere application as an Administrator. 
2. Right click on the Host object you are using and select Properties.
3. Select the Caller Access tab. 
4. Switch the authentication type to Windows or PC Anywhere.
5. If you are using PC Anywhere authentication, set a strong password.

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Unprotected PC Anywhere Service";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2002 Digital Defense Incorporated");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_dependencies("find_service.nes", "PC_anywhere_tcp.nasl");
 script_require_ports("Services/pcanywheredata", 5631);
 exit(0);
}

#
# The script code starts here
#

debug = 0;

cl[0] = raw_string (0x00, 0x00, 0x00, 0x00);
sv[0] = "nter";

cl[1] = raw_string (0x6f, 0x06, 0xff);
sv[1] = raw_string (0x1b, 0x61);

cl[2] = raw_string (0x6f, 0x61, 0x00, 0x09, 0x00, 0xfe, 0x00,
                    0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00);
                            
sv[2] = raw_string (0x1b, 0x62);

cl[3] = raw_string (0x6f, 0x62, 0x01, 0x02, 0x00, 0x00, 0x00);         
sv[3] = raw_string (0x65, 0x6e);

cl[4] = raw_string(0x6f, 0x49, 0x00, 0x4c, 0x20, 0x20, 0x20, 0x20,
                   0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x09, 0xff, 0x05, 0x00, 0x00, 0x00,
                   0x60, 0x24, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06,
                   0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                   0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                   0x31);
sv[4] = raw_string(0x1b, 0x16);

cl[5] = raw_string(0x6f, 0x73, 0x02, 0x01, 0x00, 0x02);
sv[5] = "Service Pack";

port = get_kb_item("Services/pcanywheredata");
if(!port)port = 5631;

if(get_port_state(port))
{
    soc = open_sock_tcp(port);
    if(soc)
    {

        for(d=0;cl[d];d=d+1)
        {
            if(debug)display(":: entering level ", d, "\n");
            send(socket:soc, data:cl[d]);
            r  = recv(socket:soc, length:2048);
	    if(!r)exit(0);
            
            # no minimum encryption level set
            if(d == 2)
            {
                if(("Reducing" >< r) && ("encryption" >< r))
                {
                    if(debug)display("Warning: no minimum encryption level set.\n");
                }
                if(("denying" >< r) && ("cannot connect at level" >< r))
                {
                   if(debug)display("Warning: plugin exiting because a minimum encryption level has been set.\n");
                   exit(0);                   
                }
            }
            
            # user authentication
            if(d == 3)
            {
                if(("Enter user name" >< r) || ("Enter login name" >< r))
                {
                    if(debug)display("Warning: plugin exiting because user authentication needed.\n");
                    exit(0); 
                }
            }
                       
            if( sv[d] >!< r)
            {
            
                close(soc);
                if(debug)display("exiting at level ", d, "\n");
                exit(0);
            }
        }
        security_hole(port:port);
	close(soc);
    }
}
