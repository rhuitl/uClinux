#
# Copyright (C) 2004 Tenable Network Security
#
if(description)
{
 script_id(12243);
 script_version("$Revision: 1.5 $");

 name["english"] = "H323 application detection";

 script_name(english:name["english"]);


 desc["english"] = "
Synopsis :

A Voice Over IP service is running on the remote host.

Description :

H323 is a protocol used all over the Internet.  It is used for 
Voice Over IP (VoIP), Microsoft NetMeeting, and countless other
applications.  Nessus was able to determine that the remote device
supports the H323 protocol. 

Make sure the use of this program is done in accordance with your corporate
security policy.

Solution :

If this service is not needed, disable it or filter incoming traffic
to this port.

Risk factor : 

None";



 script_description(english:desc["english"]);

 summary["english"] = "H323 application detection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 script_family(english:"Service detection");

 script_require_ports(1720);
 exit(0);
}


# start script
include("misc_func.inc");

# Thank You Ethereal and SPIKE !
function setup () 
{
    # Q.931 HEADER
    TPKT = raw_string(0x03,0x00,0x00,0x09); #version, RESERVED, 2 bytes LENGTH
    PD = raw_string(0x08);                  #protocol discriminator
    CR = raw_string(0x02);                  # Call reference value length
    CRF = raw_string(0x24);                 # call reference flag
    CRV = raw_string(0x24);                 # call reference value
    MT = raw_string(0xc2);                  # Message type (5 == setup) 
    QHEADER = TPKT + PD + CR + CRF + CRV + MT;


    # BEARER Capability
    BC = raw_string(0x05);                  # information element
    LEN = raw_string(0x04,0x03);            # length
    CS = raw_string(0x88);                  # Coding standard
    TM = raw_string(0x93);                  # transfer mode
    UI = raw_string(0xa5);                  # User info layer 1 protocol
    BHEADER = BC + LEN + CS + TM + UI;

    # DISPLAY
    IE = raw_string(0x28);                  # information element
    LEN = raw_string(0x07);                 # LEN    
    DI = string("NESSUS") + raw_string(0x00); # display info
    DHEADER = IE + LEN + DI;

    # User-User
    UU = raw_string(0x73);                 # user-user
    LEN = raw_string(0x02,0x05);           # Length
    PD = raw_string(0x20);                 # protocol discriminator

    for (i=0; i<63; i++) 
    {
        RM = RM + raw_string(rand() % 256);
    }

    UHEADER = UU + LEN + PD + RM;
 
    MREQ = QHEADER + BHEADER + DHEADER + UHEADER;
    return (MREQ);
}


# send a  short packet and look for error
port = 1720;
if (! get_port_state(port))
	exit(0);

req = setup();
soc = open_sock_tcp(port);
if (!soc) 
	exit(0);

send(socket:soc, data:req);
r = recv(socket:soc, length:1024);
close(soc);
if (r)
{
	if (ord(r[0]) == 3)
	{
		security_note(port);
		register_service(port: port, proto: "h323");
		exit(0);
	}
} 


 
