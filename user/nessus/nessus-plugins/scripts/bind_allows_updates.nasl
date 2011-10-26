#
# This checks for a common misconfiguration issue, therefore no CVE/BID
# 
#


if(description)
{
 script_id(11320);
 script_version("$Revision: 1.4 $");
 
 name["english"] = "The remote BIND has dynamic updates enabled";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote nameserver has dynamic updates enabled.

The dynamic updates let the bind administrator update the name
service information dynamically.

However, it is possible to trick bind to change the resource
record for the zone is it serves. An attacker may use this
flaw to hijack the traffic going the your servers and redirect
it to somewhere else.


Solution : If you use bind, add the option
      allow-update {none;};
      
in your named.conf to disable this feature entirely.

Risk factor : Low";

 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if the UPDATE operation is implemented on the remote host";

 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Renaud Deraison");
 family["english"] = "General";
 script_family(english:family["english"]);
 script_require_keys("DNS/udp/53");
 script_dependencies("dns_server.nasl");


 exit(0);
}


if(!get_udp_port_state(53))exit(0);

port = 53;

req = raw_string(

	  0xAB, 0xCD, 0x49, 0x00, 0x00, 0x01,
	  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x06) + "tested" + 
	 raw_string(0x02) + "by" + raw_string(0x06) + "nessus" +
	 raw_string(0x03) + "org" + 
	 raw_string(0x00, 0x00, 0x06, 0x00, 0x01, 
	 	    0x00, 0x00, 0x00, 0x00, 0x00, 0x00);
   
soc = open_sock_udp(port);
if(soc)
{
 send(socket:soc, data:req);
 r = recv(socket:soc, length:1024);
 if(r)
 {
 if(!(ord(r[2]) & 0x09) &&
    !(ord(r[3]) & 0x04))
  {
   security_warning(port: port, protocol: "udp");
  } 
 }
 exit(0);
}
