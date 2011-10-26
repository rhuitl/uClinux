#
# (C) Tenable Network Security
#


if (description)
{
  script_id(22115);
  script_version("$Revision: 1.2 $");

  script_cve_id("CVE-2006-3430");
  script_bugtraq_id(18715);

  script_name(english:"PatchLink Update checkid SQL Injection Vulnerability");
  script_summary(english:"Tries to exploit SQL injection issue in PatchLink Update");
 
  desc = "
Synopsis :

The remote web server contains an ASP script that is prone to a SQL
injection attack. 

Description :

The remote host is running PatchLink Update Server, a patch and
vulnerability management solution. 

The version of PatchLink Update Server installed on the remote fails
to sanitize user-supplied input to the 'agentid' parameter of the
'/dagent/checkprofile.php' script before using it to construct
database queries.  An unauthenticated attacker can exploit this flaw
to manipulate database queries, which might lead to disclosure of
sensitive information, modification of data, or attacks against the
underlying database. 

Note that Novell ZENworks Patch Management is based on PatchLink
Update Server and is affected as well. 

See also :

http://www.securityfocus.com/archive/1/438710/30/0/threaded
http://support.novell.com/cgi-bin/search/searchtid.cgi?10100709.htm

Solution :

Apply patch 6.1 P1 / 6.2 SR1 P1 if using PatchLink Update Server or
6.2 SR1 P1 if using Novell ZENworks Patch Management. 

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);

  script_category(ACT_ATTACK);
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


# Try to exploit the flaw to generate a SQL error.
req = http_get(
  item:string(
    "/dagent/checkprofile.asp?",
    "agentid=11111'", SCRIPT_NAME
  ),
  port:port
);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if (res == NULL) exit(0);


# There's a problem if we see an error with our script name.
if (
  "Microsoft OLE DB Provider for SQL Server" >< res &&
  "error '80040e14'" >< res &&
  # nb: the error message does not include the script's extension.
  string("Incorrect syntax near '", (SCRIPT_NAME - strstr(SCRIPT_NAME, "."))) >< res
) security_warning(port);
