 #
# (C) Tenable Network Security
#


if (description)
{
  script_id(22903);
  script_version("$Revision: 1.4 $");

  script_cve_id("CVE-2006-5478");
  script_bugtraq_id(20655);

  script_name(english:"Novell eDirectory Host Request Header Overflow Vulnerability");
  script_summary(english:"Send a special Host request header to eDirectory");

  desc = "
Synopsis :

The remote web server is affected by a buffer overflow vulnerability. 

Description :

The installed version of Novell eDirectory on the remote host
reportedly contains a buffer overflow that can be triggered with a
specially-crafted Host request header.  An anonymous remote attacker
may be able to leverage this flaw to execute code on the affected
host, generally with super-user privileges. 

See also :

http://www.mnin.org/advisories/2006_novell_httpstk.pdf.
http://archives.neohapsis.com/archives/fulldisclosure/2006-10/0434.html
http://support.novell.com/filefinder/security/index.html

Solution :

Apply the eDirectory Post 8.7.3.8 FTF1 / 8.8.1 FTF1 patch as
appropriate. 

Risk factor : 

Critical / CVSS Base Score : 10 
(AV:R/AC:L/Au:NR/C:C/A:C/I:C/B:N)";
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8028);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


function make_request (data, port)
{
 local_var req;

 # Send a special query.
 req = "";
 foreach line (split(http_get(item:"/nds", port:port)))
 {
  if ("Host: " >< line) 
    line = ereg_replace(
      pattern : "Host: .+", 
      replace : string("Host: ", data, "\r\n"),
      string  : line
    );
  req += line;
 }

 return req;
}



port = get_http_port(default:8028);
if (!get_port_state(port)) exit(0);


# Make sure the server looks like eDirectory.
banner = get_http_banner (port:port);
if (!egrep(pattern:"Server: .*HttpStk/[0-9]+\.[0-9]+", string:banner)) exit(0);


# Get the format of a normal host location

req = make_request (data:"nessus", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL)
  exit(0);

res = egrep(pattern:string("^Location: https?://nessus:[0-9]+/nds"), string:res);
if (res == NULL)
  exit (0);

# Create a special host location string

http = ereg_replace (pattern:"^Location: (https?://)nessus:[0-9]+/nds.*", string:res, replace:"\1");
sport = ereg_replace (pattern:"^Location: https?://nessus:([0-9]+)/nds.*", string:res, replace:"\1");

magic = crap(data:"A", length:62 - strlen(http) - strlen(sport));
req = make_request(data:magic, port:port);

res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);
if (res == NULL)
  exit(0);

res = egrep(pattern:string("^Location: https?://", magic, ":[0-9]+/nds"), string:res);
if (res == NULL)
  exit (0);

s = ereg_replace (pattern:"^Location: (https?://A+:[0-9]+/nds).*", string:res, replace:"\1");

# Patched version should skip 1 character in the port number
if (strlen(s) == 67)
  security_hole(port);
