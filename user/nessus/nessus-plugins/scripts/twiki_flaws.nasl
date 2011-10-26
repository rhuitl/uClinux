#
# This script is (C) Tenable Network Security
#
#

if(description)
{
 script_id(17210);
 script_cve_id("CVE-2005-0516");
 script_bugtraq_id(12637, 12638);
 script_version ("$Revision: 1.4 $");
 name["english"] = "TWiki Multiple Vulnerabilties";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server contains a CGI application that is affected by
arbitrary command execution flaws.

Description :

According to its version number, the remote installation of TWiki is
vulnerable to several input validation vulnerabilities that may allow
an attacker to execute arbitary commands on the remote host with the
privileges of the web server. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=110918725225288&w=2

Solution : 

Apply the TWiki robustness patch referenced in the advisory above. 

Risk factor : 

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for the presence of TWiki";
 
 script_summary(english:summary["english"]);
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security",
		francais:"Ce script est Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("twiki_detect.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);

# Test an install.
install = get_kb_item(string("www/", port, "/twiki"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  ver = matches[1];

  if (egrep(pattern:"(1999|200[0-4])", string:ver)) 
    security_hole(port);
}
