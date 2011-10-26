# Ferdy Riphagen and Josh Zlatin-Amishav
# GPLv2

desc = "
Synopsis :

The remote system is a SIP signaling device. 

Description :

The remote system is running software that speaks the Session
Initiation Protocol. 

SIP is a messaging protocol to initiate communication sessions between
systems.  It is a protocol used mostly in IP Telephony networks /
systems to setup, control and teardown sessions between two or more
systems. 

See also :

http://en.wikipedia.org/wiki/Session_Initiation_Protocol

Solution :

If possible, filter incoming connections to the port so that it is
used by trusted sources only. 

Risk factor :

None";

if (description) {
script_id(21642);
script_version("$Revision: 1.10 $");

name["english"] = "Session Initiation Protocol Detection";
script_name(english:name["english"]);
script_description(english:desc); 

summary["english"] = "Checks if the remote system understands the SIP protocol";
script_summary(english:summary["english"]);

script_category(ACT_GATHER_INFO);
script_family(english:"Service detection");
script_copyright(english:"This script is Copyright (C) 2006 Ferdy Riphagen and Josh Zlatin-Amishav");
exit(0);
}

include("misc_func.inc");

debug = 0;
port = 5060;

if (!get_udp_port_state(port)) exit(0);

# Check if we are scanning our local system.
# If so we can't use source port 5060, but it is worth a try.
if (islocalhost()) {
 soc = open_sock_udp(port);
}
# Some systems (such as the Cisco 7905G IP Phone) only want to talk if 
# the source port is 5060.
else soc = open_priv_sock_udp(sport:5060, dport:port);
if (!soc) exit(0);


# Generate the 'SIP' OPTIONS packet
query = string("OPTIONS sip:", get_host_name(), " SIP/2.0", "\r\n",
               "Via: SIP/2.0/UDP ", this_host(), ":", port, "\r\n",
               "Max-Forwards: 70\r\n",
               "To: <sip:", this_host(), ":", port, ">\r\n",
               "From: Nessus <sip:", this_host(), ":", port, ">\r\n",
               "Call-ID: ", rand(), "\r\n",
               "CSeq: 63104 OPTIONS\r\n",
               "Contact: <sip:", this_host(), ">\r\n",
               "Accept: application/sdp\r\n",
               "Content-Length: 0\r\n\r\n");


if (debug) display("query: ", query, "\n");

send(socket:soc, data:query);
res = recv(socket:soc, length:1024);

if (!isnull(res))  
{
  if (debug) display("res: ", res, "\n");
  # If it looks like a SIP packet
  if ( "SIP/2.0/UDP" >< res)
  {
    # Try to get details
    if ("Server:" >< res)
    {
      banner = egrep(pattern: '^Server:', string: res);
      banner = substr(banner, 8);
    }
    else if ("User-Agent" >< res )
    {
      # Note: Asterisk SIP servers don't return a Server banner
      banner = egrep(pattern: '^User-Agent', string: res);
      banner = substr(banner, 12);
    }

    # Also try to report the remote capabilities.
    if (egrep(pattern:"^Allow:.+OPTIONS", string:res))
    {
      options = egrep(pattern:"^Allow:.+OPTIONS", string:res);
      if (options) options = options - string("Allow: ");
    }

    if (debug)
    {
      display("options: ", options, "\n");
      display("banner: ", banner, "\n");
    }
    
    if (!isnull(banner))
    {
      banner = chomp(banner);
      desc = string( 
        desc, 
	"\n\n", 
	"The remote service was identified as :\n", banner  
      );
      set_kb_item(name:"sip/banner/" + port, value:banner); 
    }

    if (!isnull(options))
    {
      desc = string( 
        desc, 
	"\n\n", 
	"The system supports the following options :\n", options
      );
    }
    register_service(ipproto:"udp", proto:"sip", port:port);
    security_note(port:port, protocol:"udp", data:desc);
  }
}
