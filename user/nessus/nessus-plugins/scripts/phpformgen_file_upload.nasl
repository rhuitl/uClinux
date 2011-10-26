#
# (C) Tenable Network Security
#


  desc = "
Synopsis :

The remote web server contains a PHP application that is affected by
an arbitrary file upload vulnerability. 

Description :

The remote host is running phpFormGenerator, a PHP-based tool for
generating web forms. 

The version of phpFormGenerator installed on the remote host allows an
unauthenticated attacker to create forms supporting arbitrary file
uploads.  He can then leverage this issue to upload a file with
arbitrary code and execute it subject to the privileges of the web
server user id. 

See also :

http://exploitlabs.com/files/advisories/EXPL-A-2006-004-phpformgen.txt

Solution :

Unknown at this time. 

Risk factor :

High / CVSS Base Score : 7 
(AV:R/AC:L/Au:NR/C:P/A:P/I:P/B:N)";


if (description)
{
  script_id(21918);
  script_version("$Revision: 1.1 $");

  script_bugtraq_id(18768);

  script_name(english:"phpFormGenerator Arbitrary File Upload Vulnerability");
  script_summary(english:"Tries to execute arbitrary code using phpFormGenator");
 
  script_description(english:desc);
 
  script_category(ACT_DESTRUCTIVE_ATTACK);
  script_family(english:"CGI abuses");
 
  script_copyright(english:"This script is Copyright (C) 2006 Tenable Network Security");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_php(port:port)) exit(0);


# Loop through various directories.
if (thorough_tests) dirs = make_list("/phpformgenerator", "/phpform", "/forms", "/form", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the form exists.
  res = http_get_cache(item:string(dir, "/index.php"), port:port);
  if (res == NULL) exit(0);

  # If it does...
  if (
    '<td align="right" class="small">opensource design' &&
    '<form action="fields.php"' >< res
  )
  {

    # Create a form with a file upload field.
    fname = rand_str(charset:"abcdefghijklmnopqrstuvwxyz0123456789_");
    postdata = string(
      "FormName=", fname, "&",
      # nb: bogus email, needed to get by email validity check.
      "email=nessus@nessus.zzfo&",
      "redirect=&",
      "gen_thank=on&",
      "template_name=default&",
      "db=no&",
      "hostname=&",
      "dbuser=&",
      "dbpass=&",
      "dbname=&",
      "table_name=&",
      "tab_name=&",
      "column[0]=", SCRIPT_NAME, "&",
      "name[0]=", fname, "&",
      "type[0]=file_upload&",
      "size1[0]=&",
      "size2[0]=&",
      "required[0]=&",
      "active[0]=&",
      "hvalue[0]=&",
      "evalue[0]=",
      "fields=1"
    );
    req = string(
      "POST ", dir, "/process3.php HTTP/1.1\r\n",
      "Host: ", get_host_name(), "\r\n",
      "User-Agent: ", get_kb_item("global_settings/http_user_agent"), "\r\n",
      "Content-Type: application/x-www-form-urlencoded\r\n",
      "Content-Length: ", strlen(postdata), "\r\n",
      "\r\n",
      postdata
    );
    res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
    if (res == NULL) exit(0);

    # There's a problem if the form was created.
    #
    # nb: the app will email the actual location of the file to the
    #     address supplied when creating the form; alternatively, an 
    #     attacker could likely guess the filename from the server's
    #     Date response header -- the name is of the form 
    #     "hh_mm_ss_filename".
    if (string("reach it by clicking <a href='use/", fname, "/form1.html'>") >< res)
    {
      report = string(
        desc,
        "\n\n",
        "Plugin output :\n",
        "\n",
        "Nessus created a file upload form on the remote host; please\n",
        "delete it as soon as possible :\n",
        "\n",
        "  ", dir, "/use/", fname, "/form1.html\n"
      );
      security_hole(port:port, data:report);
      exit(0);
    }
  }
}
