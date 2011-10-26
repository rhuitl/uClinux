#
# This script was written by Javier Fernandez-Sanguino
# based on sample code written by Renaud Deraison <deraison@cvs.nessus.org>
# in the nessus-plugins mailing list
#
# It is distributed under the GPL license, you can find a copy of this license
# in http://www.gnu.org/copyleft/gpl.html
# 

    desc["english"] = "
Synopsis :

The remote web server contains a graphic image that is prone to
information disclosure. 

Description :

The 'favicon.ico' file found on the remote web server belongs to a
popular webserver.  This may be used to fingerprint the web server. 

Solution: 

Remove the 'favicon.ico' file or create a custom one for your site. 

Risk factor: 

Low / CVSS Base Score : 2
(AV:R/AC:L/Au:NR/C:P/A:N/I:N/B:N)";

if(description) {
    script_id(20108); 
    script_version ("$Revision: 1.3 $");

    name["english"] = "Fingerprint web server with favicon.ico";
    script_name(english:name["english"]);
    summary["english"] = "Attempt to fingerprint web server with favicon.ico";
    script_summary(english:summary["english"]);

    script_description(english:desc["english"]);

    script_category(ACT_GATHER_INFO);
    script_copyright(english:"This script is Copyright (C) 2005 Javier Fernandez-Sanguino"); 
    family["english"] = "CGI abuses";
    script_family(english:family["english"]);
    script_dependencie("http_version.nasl");
    script_require_ports("Services/www", 80);
    exit(0);
}


# Script code starts here

# Requirements
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);


# Make the request
req = http_get(item:"/favicon.ico", port:port);
res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
if ( res == NULL ) exit(0);
md5 = hexstr(MD5(res));


# Known favicons list:
#
# Google Web Server, should not be seen outside Google, and servers as
# a way to test the script
server["4987120f4fb1dc454f889e8c92f6dabe"] = "Google Web Server";

# RedHat's icon in Apache web server
server["71e30c507ca3fa005e2d1322a5aa8fb2"] = "Apache on Redhat";

# SunOne 6.1, based on Netscape Enterprise
server["a28ebcac852795fe30d8e99a23d377c1"] = "SunOne 6.1";

# Netscape 6.0 as distributed by AOL
server["41e2c893098b3ed9fc14b821a2e14e73"] = "Netscape 6.0 (AOL)";

# Netscape 6.0 as distributed by Sun (iPlanet)
server["b25dbe60830705d98ba3aaf0568c456a"] = "Netscape iPlanet 6.0";

# Netscape 4.1
server["226ffc5e483b85ec261654fe255e60be"] = "Netscape 4.1";

# NetScreen
server["f1876a80546b3986dbb79bad727b0374"] = "NetScreen WebUI";

# Check the hash against what we know about.
if (server[md5]) {
  if (report_verbosity > 0) {
    report = string(
      desc["english"],
      "\n\n",
      "Plugin output :\n",
      "\n",
      "The 'favico.ico' fingerprints this webserver as ", server[md5], "."
    );
  }
  else report = desc["english"];

  security_note(port:port, data:report);
  exit(0);
}


# This is a sample script to obtain the list of favicon files from a Webscarab
# directory. Can be useful to add new favicon after a pen-test:
# 
##!/bin/sh
#
#pwd=`pwd`
#find . -name "*response*" |
#while read file ; do
#	if grep -q "^Content-type: image/x-icon" $pwd/$file; then
#	# It's an ico file
#
#	server=`grep --binary-files=text "^Server" $pwd/$file`
#	size=`stat -c %B $pwd/$file`
#		if [ ! -n "$server" ] 
#		then
#			server=`echo $server | sed -e 's/Server: //'`
#		else
#			server="unknown"
#		fi
#	echo "$server,$file,$size"
#	fi
#done

