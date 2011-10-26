#
# This script was written by David Maciejak <david dot maciejak at kyxar dot fr>
# Ref: Siegfried and netcraft
#
# This script is released under the GNU GPLv2
#

if(description)
{
 script_id(20978);
 script_version ("$Revision: 1.2 $");

 script_cve_id("CVE-2006-0517", "CVE-2006-0518", "CVE-2006-0519");
 script_bugtraq_id(16458, 16461);
  
 name["english"] = "SPIP < 1.8.2-g SQL Injection and XSS Flaws";
 script_name(english:name["english"]);
 
 desc["english"] = "
Synopsis :

The remote web server has a PHP application that is affected by
multiple flaws. 

Description:

The remote host is running SPIP, an open-source CMS written in PHP. 

The remote version of this software is prone to SQL injection and
cross site scripting attacks.  An attacker could send specially
crafted URL to modify SQL requests, for example, to obtain the admin
password hash, or execute malicious script code on the remote system. 

See also :

http://www.zone-h.org/en/advisories/read/id=8650/
http://www.securityfocus.com/archive/1/423655/30/0/threaded
http://listes.rezo.net/archives/spip-en/2006-02/msg00002.html
http://listes.rezo.net/archives/spip-en/2006-02/msg00004.html

Solution :

Upgrade to SPIP version 1.8.2-g or later. 

Risk factor :

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";

 script_description(english:desc["english"]);
 
 summary["english"] = "Checks for SPIP SQL injection flaw";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
  
 script_copyright(english:"This script is Copyright (C) 2006 David Maciejak");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# the code
#

 include("http_func.inc");
 include("http_keepalive.inc");

 port = get_http_port(default:80);
 if(!get_port_state(port))exit(0);
 if (!can_host_php(port:port) ) exit(0);

 # Check a few directories.
 if (thorough_tests) dirs = make_list("/spip", cgi_dirs());
 else dirs = make_list(cgi_dirs());

 foreach dir (dirs)
 { 
  files=make_list("forum.php3", "forum.php");
  foreach file (files)
  {
        magic = rand();
	req = http_get(item:string(dir,"/",file,'?id_article=1&id_forum=-1/**/UNION/**/SELECT%20', magic, '/*'), port:port);
        res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
        if (res == NULL) exit(0);

        if (string('value="&gt; ', magic, '" class="forml"') >< res) {
          security_warning(port:port, data:desc);
	  exit(0);
	}
  }
}
