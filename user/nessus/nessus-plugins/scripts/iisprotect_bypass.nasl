#
# (C) Tenable Network Security
#
# See the Nessus Scripts License for details
#
# Note that we need to be authenticated for this check
# to work properly.
#


if(description)
{
 script_id(11663);
 script_bugtraq_id(7661);
 script_version("$Revision: 1.9 $");
 
 name["english"] = "iiprotect bypass";
 script_name(english:name["english"]);
 
 desc["english"] = "
The remote host seems to be running iisprotect, an IIS add-on to protect the
pages served by this server.

There is a bug in the remote version of iisprotect which may allow
an attacker to bypass protection by hex-encoding the requested URLs.

Solution : Upgrade to iisprotect 2.2
Risk factor : High";


 script_description(english:desc["english"]);
 
 summary["english"] = "Determines if iisprotect can be escaped";
 
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003 Tenable Network Security");
 family["english"] = "CGI abuses";
 family["francais"] = "Abus de CGI";
 script_family(english:family["english"], francais:family["francais"]);
 script_dependencie("find_service.nes", "http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# Check starts here

include("http_func.inc");
include("http_keepalive.inc");

function encode(dir)
{
 for(i=strlen(dir) - 2;i>1;i--)
 {
  if(dir[i] == "/")break;
 }
 if(i <= 1)return NULL;
 
 enc = "%" + hex(ord(dir[i+1])) - "0x";
 dir = insstr(dir, enc, i+1, i+1);
 return dir;
}
function check(loc)
{
 req = http_get(item:loc, port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if( res == NULL ) exit(0);
 if(ereg(pattern:"HTTP/[0-9]\.[0-9] (40[13]|30[0-9]) ", string:res))return 300;
 else if(ereg(pattern:"HTTP/[0-9]\.[0-9] 200 ", string:res))return 200;
 else return -1;
}

port = get_http_port(default:80);


dirs = get_kb_list(string("www/", port, "/content/auth_required"));
if(!isnull(dirs))dirs = make_list(dirs, "/iisprotect/sample/protected");
else dirs = make_list("/iisprotect/sample/protected");

if(get_port_state(port))
{
 foreach dir (dirs)
 {
  if( check(loc:dir) == 300 )
  {
   origdir = dir;
   dir = encode(dir:dir);
   if( dir && check(loc:dir) == 200 )
   {
report = "
The remote host seems to be running iisprotect, an IIS add-on to protect the
pages served by this server.

There is a bug in the remote server which may allow an attacker to
obtain access to otherwise protected pages by hex-encoding the URLs.

For instance, the url :

	" + origdir + " 

is protected (code 30x) but the URL :

	" + dir + "

is does not ask for a password (code 200).

Solution : Upgrade to iisprotect 2.2 or contact your vendor for a patch
Risk factor : High";
    security_hole(port:port, data:report);
    exit(0);
    }
  }
 }
}
