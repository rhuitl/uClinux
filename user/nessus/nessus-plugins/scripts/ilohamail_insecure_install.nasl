#
# (C) Tenable Network Security
#



if (description) {
  script_id(16161);
  script_version("$Revision: 1.2 $");
  script_bugtraq_id(12252);

  desc["english"] = "
The remote host is running Ilohamail, a web-based mail interface written
in PHP.

The remote installation of this software is not configured properly,
in the sense that it allows any user to download its configuration
files by requesting one of these files :

	/conf/conf.inc
	/conf/custom_auth.inc

The content of these files may contain sensitive information which may
help an attacker to organize better attacks against the remote host.

Solution : Prevent the download of .inc files at the web server level
Risk Factor : Medium";
 
  name["english"] = "IlohaMail Insecure Install";
  script_name(english:name["english"]);
 
  script_description(english:desc["english"]);
 
  summary["english"] = "Checks for the presence of conf/conf.inc";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

# use ilohamail_conf_files_readable.nasl instead
exit (0);

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);

res = http_keepalive_send_recv(data:http_get(item:"/conf/conf.inc", port:port), port:port);
if ( res == NULL ) exit(0);

if ( egrep(pattern:"\$backend *=", string:res)  &&
     egrep(pattern:"\$USER_DIR", string:res) )
	security_warning(port);
