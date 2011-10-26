#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#

if(description)
{
 script_id(10056);
 script_bugtraq_id(318);
 script_version ("$Revision: 1.18 $");
 script_cve_id("CVE-1999-0678");
 name["english"] = "/doc directory browsable ?";
 script_name(english:name["english"]);
 
 desc["english"] = "The /doc directory is browsable.
/doc shows the content of the /usr/doc directory and therefore it shows which programs and - important! - the version of the installed programs.

Solution : Use access restrictions for the /doc directory.
If you use Apache you might use this in your access.conf:

 <Directory /usr/doc>
 AllowOverride None
 order deny,allow
 deny from all
 allow from localhost
 </Directory>

Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Is /doc browsable ?";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2000 Hendrik Scholz");

 family["english"] = "CGI abuses";
 script_family(english:family["english"]);

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
 data = http_get(item:"/doc/", port:port);
 buf = http_keepalive_send_recv(port:port, data:data);
 buf = tolower(buf);
 must_see = "index of /doc";

  if((ereg(string:buf, pattern:"^http/[0-9]\.[0-9] 200 "))&&(must_see >< buf)){
    	security_warning(port);
	set_kb_item(name:"www/doc_browseable", value:TRUE);
  }
}

