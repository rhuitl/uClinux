#
# (C) Tenable Network Security
#

if (description) {
  script_id(15403);
 script_cve_id("CVE-2004-1566", "CVE-2004-1567");
  script_bugtraq_id(11284);
  script_version("$Revision: 1.5 $");
 
  name["english"] = "Silent-Storm Portal Multiple Input Validation Vulnerabilities";
  script_name(english:name["english"]);
 
  desc["english"] = "
The remote host is running Silent-Storm, a web-based forum management software
written in PHP.

There are multiple input validation flaws in the remote version of this 
software :

- There is a cross site scripting vulnerability affecting the file 'index.php'
- An attacker may corrupt the user database by creating a malformed username

Solution : Upgrade to the newest version of this software.
Risk factor : Medium";
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for vulnerabilities in Silent-Storm Portal";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");


function check(dir)
{
  req = http_get(item:dir + "/index.php?module=<script>foo</script>", port:port);
  buf = http_keepalive_send_recv(port:port, data:req);
  if(buf == NULL)exit(0);

  if("<script>foo</script>" >< buf && "copyright silent-storm.co.uk" >< buf )
  	{
	security_warning(port);
	exit(0);
	}
 
 
 return(0);
}

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);


foreach dir (cgi_dirs()) 
 {
  check( dir : dir );
 }
