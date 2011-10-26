#
# Script by Josh Zlatin-Amishav GPLv2
#

 desc["english"] = "
Synopsis :

The remote web server contains a web application framework written in
PHP. 

Description :

This script detects whether the remote host is running Xaraya and
extracts the version number and location if found. 

Xaraya is an extensible, open-source web application framework written
in PHP.  

See also :

http://www.xaraya.com/

Risk factor :

None";


if(description)
{
 script_id(19426);
 script_version("$Revision: 1.3 $");
 
 name["english"] = "Detects Xaraya version";

 script_name(english:name["english"]);
 
 script_description(english:desc["english"]);
 
 summary["english"] = "Xaraya detection";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"Copyright (C) 2005 Josh Zlatin-Amishav");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(!can_host_php(port:port)) exit(0);


if (thorough_tests) dirs = make_list("/xaraya", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
 res = http_get_cache(item:string(dir, "/index.php"), port:port);
 #display("res[", res, "]\n");
 if (res == NULL) exit(0);

 if (
   # Cookie from Xaraya
   "^Set-Cookie: XARAYASID=" >< res ||
   # Meta tag from Xaraya
   "^X-Meta-Generator: Xaraya ::" >< res ||
   # Xaraya look-and-feel
   egrep(string:res, pattern:'div class="xar-(alt|block-.+|menu-.+|norm)"')
 ) {
   if (dir == "") dir = "/";

   # Look for the version number in a meta tag.
   pat = 'meta name="Generator" content="Xaraya :: ([^"]+)';
   matches = egrep(pattern:pat, string:res);
   if (matches) {
     foreach match (split(matches))
     {
       ver = eregmatch(pattern:pat, string:match);
       if (!isnull(ver))
       {
         ver = ver[1];
         info = string("Xaraya version ", ver, " is installed on the remote host\nunder the path ", dir, ".");
         break;
       }
     }
   }

   if (isnull(ver))
   {
     ver = "unknown";
     info = string("An unknown version of Xaraya is installed on the remote host\nunder the path ", dir, ".");
   }

   set_kb_item(
     name:string("www/", port, "/xaraya"),
     value:string(ver, " under ", dir)
   );

   desc["english"] += '\n\nPlugin output :\n\n' + info;
   security_note(port:port, data:desc["english"]);

   exit(0);
  }
}
