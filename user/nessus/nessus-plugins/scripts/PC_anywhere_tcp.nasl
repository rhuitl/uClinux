#
# This script was written by Georges Dagousset <georges.dagousset@alert4web.com>
#
# Changes by Tenable Network Security : cleanup + better detection
#
# See the Nessus Scripts License for details
#

if(description)
{
 script_id(10794);
 script_version ("$Revision: 1.29 $");
 name["english"] = "pcAnywhere TCP";
 script_name(english:name["english"]);

 desc["english"] = "pcAnywhere is running on this port

Solution : Disable this service if you do not use it.

Risk factor : None";

 script_description(english:desc["english"]);
 summary["english"] = "Checks for the presence pcAnywhere";
 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2001 Alert4Web.com");

 family["english"] = "Windows";
 script_family(english:family["english"]);
 script_dependencie("os_fingerprint.nasl", "find_service.nes");
 script_require_ports("Services/unknown", 5631);
 exit(0);
}

include("misc_func.inc");
include("global_settings.inc");

os = get_kb_item("Host/OS/smb");
if (!os || ("Windows" >!< os))
  exit(0);


function probe(port)
{
 soc = open_sock_tcp(port);
 if(soc)
 {
    send(socket:soc, data:raw_string(0,0,0,0));
    r = recv(socket:soc, length:36);
    if (r && ("Please press <" >< r))
    {
       register_service(port:port, proto:"pcanywheredata");
       security_note(port);
       exit(0);
    }
  close(soc);
 }
}



if ( thorough_tests ) {
	 port = get_unknown_svc(5631);
	 if ( ! port ) exit(0);
	}
else port = 5631;

if(get_port_state(port)) probe(port:port);

