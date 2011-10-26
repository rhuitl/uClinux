#
# (C) Tenable Network Security
# 

 desc["english"] = "
Synopsis :

The remote web server is affected by an information disclosure flaw. 

Description :

The remote JBoss server is vulnerable to an information disclosure
flaw which may allow an attacker to retrieve the physical path of the
server installation, its security policy, or to guess its exact
version number.  An attacker may use this flaw to gain more
information about the remote configuration. 

See also :

http://marc.theaimsgroup.com/?l=bugtraq&m=111911095424496&w=2
http://www.securityfocus.com/advisories/10104

Solution : 

Upgrade to JBoss 3.2.8 or 4.0.3.  Or edit JBoss' 'jboss-service.xml'
configuration file, set 'DownloadServerClasses' to 'false', and
restart the server. 

Risk factor : 

Low / CVSS Base Score : 2.3
(AV:R/AC:L/Au:NR/C:P/I:N/A:N/B:N)";


if(description)
{
 script_id(18526);

 script_cve_id("CVE-2005-2006", "CVE-2006-0656");
 script_bugtraq_id(13985, 16571);

 script_version("$Revision: 1.4 $");
 
 name["english"] = "JBoss Malformed HTTP Request Remote Information Disclosure";
 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Attempts to read security policy of a remote JBoss server";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 8083, 50013);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


ports = get_kb_list("Services/www");
ports = add_port_in_list(list:ports, port:8083);
ports = add_port_in_list(list:ports, port:50013);

foreach port (ports) {
  if (get_port_state(port)) {
    req = http_get(item:"%.", port:port);
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:FALSE);

    if (res && ereg(pattern:"^HTTP/.* 400 (/|[A-Z]:\\)", string:res)) {
      file = "server.policy";
      req = http_get(item:"%"+file, port:port);
      res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
      
      if (res && "JBoss Security Policy" >< res) {
        report = string(
          desc["english"],
          "\n\n",
          "Plugin output :\n",
          "\n",
          "Here are the contents of the file '", file, "' that\n",
          "Nessus was able to read from the remote host :\n",
          "\n",
          res
        );

        security_note(port:port, data:report);
      }
    }
  }
}
