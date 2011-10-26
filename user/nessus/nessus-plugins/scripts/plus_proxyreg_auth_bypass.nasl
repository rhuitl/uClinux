#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains an ASP script that is prone to an
authentication bypass attack. 

Description :

The remote host is running PatchLink Update Server, a patch and
vulnerability management solution. 

The version of PatchLink Update Server installed on the remote fails
to check for authentication credentials before providing access to the
'/dagent/proxyreg.asp' script.  An attacker can exploit this issue to
list, delete, or add proxies used by the PatchLink FastPatch software. 

Note that Novell ZENworks Patch Management is based on PatchLink
Update Server and is affected as well. 

See also :

http://www.securityfocus.com/archive/1/438710/30/0/threaded
http://support.novell.com/cgi-bin/search/searchtid.cgi?10100709.htm

Solution :

Apply patch 6.1 P1 / 6.2 SR1 P1 if using PatchLink Update Server or
6.2 SR1 P1 if using Novell ZENworks Patch Management. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(22117);
  script_version("$Revision: 1.1 $");

  script_cve_id("CVE-2006-3425");
  script_bugtraq_id(18723);

  script_name(english:"PatchLink Update Server proxyreg.asp Authentication Bypass Vulnerability");
  script_summary(english:"Tries to list registered proxy server in PatchLink Update Server");
 
  script_description(english:desc);

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);


# Try to list registered proxy servers.
req = http_get(item:"/dagent/proxyreg.asp?List=", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we get a listing.
if ("registered as distribution point servers for this PatchLink Update Server" >< res)
{
  # Identify proxies.
  proxies = "";
  content = res;
  while (content = strstr(content, "<tr><td>"))
  {
    match = eregmatch(pattern:"<tr><td>([^<]+)</td><td>([^<]+)</td", string:content);
    if (match) proxies += "  " + match[1] + ":" + match[2] + '\n';
    content = content - "<tr><td>";
  }
  if (!proxies) proxies = "  none";

  report = string(
    desc,
    "\n\n",
    "Plugin output :\n",
    "\n",
    "The following is the list of currently configured proxies :\n",
    "\n",
    proxies
  );
  security_hole(port:port, data:report);
}
