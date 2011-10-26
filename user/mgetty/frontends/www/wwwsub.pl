#
# mgetty WWW gui common "things"
#
# RCS: $Id: wwwsub.pl,v 1.6 2004/11/17 14:12:55 gert Exp $
#
# $Log

# common HTML error handler - print error message, end program
sub errormessage
{
    my $message = shift;
    print <<EOF;
<html><head><title>Configuration Error</title></head><body bgcolor="#ffffff">
<h1><p><b><blink>Configuration Error</blink> - - $message</b></p></h1>
</body></html>
EOF
    exit 1;
}
# end errormessage


#
# all necessary checks for $fax_outgoing, $fax_incoming
#
sub check_outgoing { check_directory($fax_outgoing, "fax_outgoing"); }
sub check_incoming { check_directory($fax_incoming, "fax_incoming"); }

#
# all necessary checks for a directory
#
sub check_directory
{

    my $directory = shift;
    my $string = shift;
    # check if directory is defined
    if ($directory eq "")
    {
	errormessage("\$$string : not configured - please look at the configuration-Files and configure the Directory where you store your outgoing faxes (\$$directory)");
    }

    # check, if directory exists
    if (! -d $directory)
    { errormessage("\$$string : no such directory $directory");}

    # check, if directory has read-permissions
    if (! -r $directory)
    { errormessage("\$string : no read-permission for $directory (running with UID: $<)");}
}
# end check_directory


# get variables and infos from CGI
sub get_cgi
{
    my $do_plus = shift;

    ### GET or POST?
    if ($ENV{'REQUEST_METHOD'} eq "GET")
    {
       $query_string=$ENV{'QUERY_STRING'};
    }
    elsif (($ENV{'REQUEST_METHOD'} eq "POST") &&
	  ($ENV{'CONTENT_TYPE'} eq "application/x-www-form-urlencoded"))
    {
       read(STDIN,$query_string,$ENV{'CONTENT_LENGTH'});
    }
    else
    {
        $query_string="";
	return 0;
    }

    ### parse arguments
    %args=();
    foreach (split(/\&/,$query_string))
    {
       if ( /^(\w+)=(.+)/ )
       {
	  ( $key, $value ) = ($1, $2);

	  if ($do_plus) {$value =~ s/\+/ /go;}
	  $value =~ s/\%([0-9a-f]{2})/pack(C,hex($1))/eig;
     
          if ( !defined $args{"$key"} ) { $args{"$key"} = ''; }
	  $args{"$key"}=$args{"$key"} . " " . $value if ($value!~/^\s*$/);
	  $args{"$key"} =~ s/^\s+//o;
       }
    }

    return 1;
}
# end get_cgi

1;
