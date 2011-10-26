#
# (C) Tenable Network Security
#


if (description) 
{
  script_id(22089);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(18984);

  script_name(english:"Invision Power Board CLIENT_IP SQL Injection Vulnerability");
  script_summary(english:"Checks version of IPB");
 
  desc = "
Synopsis : 

The remote web server contains a PHP application that is susceptible
to a SQL injection attack. 

Description :

According to its banner, the installation of Invision Power Board on
the remote host reportedly fails to sanitize input to the 'CLIENT_IP'
HTTP request header before using it in database queries.  An
unauthenticated attacker may be able to leverage this issue to
disclose sensitive information, modify data, or launch attacks against
the underlying database. 

Note that it's unclear whether successful exploitation depends on any
PHP settings, such as 'magic_quotes'. 

See also :

http://www.milw0rm.com/exploits/2010
http://www.nessus.org/u?eea8694e

Solution :

Upgrade to Invision Power Board 2.1.7 or later. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("invision_power_board_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Test an install.
install = get_kb_item(string("www/", port, "/invision_power_board"));
if (isnull(install)) exit(0);
matches = eregmatch(pattern:"^(.+) under (/.*)$", string:install);
if (!isnull(matches))
{
  ver = matches[1];

  if (ver && ver =~ "^([01]\.|2\.(0\.|1\.[0-6][^0-9]?))")
  {
    security_hole(port);
    exit(0);
  }
}
