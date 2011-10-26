#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#


if(description)
{
 script_id(11653);
 script_version ("$Revision: 1.8 $");

 script_bugtraq_id(5504, 5509, 5510, 5514, 5515, 5563, 5565);
 script_cve_id("CVE-2002-1110", "CVE-2002-1111", "CVE-2002-1112", "CVE-2002-1113", "CVE-2002-1114", "CVE-2002-1115");
 script_xref(name:"OSVDB", value:"4858");

 name["english"] = "Mantis Multiple Flaws";
 
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a PHP application that is affected by
several flaws. 

Description :

According to its banner, the version of Mantis on the remote host
contains various flaws that may allow an atacker to execute arbitrary
commands, inject SQL commands, view bugs it should not see, and get a
list of projects that should be hidden.

See also :

http://archives.neohapsis.com/archives/bugtraq/2002-08/0176.html
http://archives.neohapsis.com/archives/bugtraq/2002-08/0177.html
http://archives.neohapsis.com/archives/bugtraq/2002-08/0184.html
http://archives.neohapsis.com/archives/bugtraq/2002-08/0186.html
http://archives.neohapsis.com/archives/bugtraq/2002-08/0187.html
http://archives.neohapsis.com/archives/bugtraq/2002-08/0253.html
http://archives.neohapsis.com/archives/bugtraq/2002-08/0255.html

Solution : 

Upgrade to Mantis 0.17.5 or newer.

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the version of Mantis";
 
 script_summary(english:summary["english"], francais:summary["francais"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("mantis_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("http_func.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/mantis"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if(ereg(pattern:"^0\.([0-9]\.|1[0-6]\.|17\.[0-4][^0-9])", string:ver))
	security_hole(port);
}	
