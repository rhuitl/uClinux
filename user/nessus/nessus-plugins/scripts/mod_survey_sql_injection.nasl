#
# This script was written by Renaud Deraison

if(description)
{
 script_id(11609);
 script_bugtraq_id(7192);
 script_version("$Revision: 1.4 $");
 name["english"] = "mod_survey ENV tags SQL injection";
 script_name(english:name["english"]);

 desc["english"] = "
The remote web server is running mod_survey, a perl add-on
to manage online surveys.

There is a flaw in the remote installation of mod_survey
which makes it vulnerable to SQL injection when a database
backend is used.

An attacker may use this flaw to take the control of your
database.


Solution : Upgrade to mod_survey 3.0.14e or 3.0.15pre6
Risk factor : High";

 script_description(english:desc["english"]);

 summary["english"] = "mod_survey SQL injection";

 script_summary(english:summary["english"]);

 script_category(ACT_GATHER_INFO);


 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "Web Servers";
 script_family(english:family["english"]);
 script_dependencie("find_service.nes", "httpver.nasl", "no404.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");



 
port = get_http_port(default:80);


if(!get_port_state(port))exit(0);



files = get_kb_list(string("www/",port, "/content/extensions/survey"));
if(!isnull(files))
 {
  files = make_list(files);
  req = http_get(item:files[0], port:port);
  res = http_keepalive_send_recv(port:port, data:req);
  if(res == NULL) exit(0);
  
  if("Mod_Survey" >< res)
  {
   if(egrep(pattern:"Mod_Survey v([0-2]\.|3\.0\.([0-9][^0-9]|1[0-3]|14[^a-z]|14[a-d]|15pre[0-5]))", 
   	   string:res)){ security_hole(port); exit(0); }
  }
 }
