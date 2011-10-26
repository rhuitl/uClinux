#!/usr/bin/perl
###########################################################
#
# @(#) mail2fax.pl - Convert an email message to a fax
#
# The mail message is expected at STDIN or in an optionally
#  specified file, the output will be written to a temp.
#  file and handed into the FAX system from there.
#
# 1.00 05-Jun-1995 TB   First version
# 2.00 14-Aug-1995 TB   Added check for User and Password
#                       Added billing
#                       Added configuration file
#
###########################################################
#
# Configurable items

# The configuration file. For a description see the
#  correspoding file in this distribution.
$ConfFile = "/usr/local/etc/mail2fax.rc";

###########################################################
# Constants
($ProgName = $0) =~ s%.*/%%;
$Version = "2.00";
$CopyRight = "(c) Copyright 1995 Thomas Bullinger";
$Billing = 1;
$Debug = 0;
$Unknown = "unknown";

###########################################################
# Inform the sender about missing FAX number
sub MissingNo {
    # Inform the original sender that the fax is rejected
    open (MAILFILE, "| $MailCmd $MailCmdOptions") || die ("ERROR: Can not notify requestor\n");
    print MAILFILE "From: MAIL2FAX gateway (mail2fax)\n";
    print MAILFILE "To: $From\n";
    print MAILFILE "Subject: Re: Your FAX is rejected\n";
    print MAILFILE "Date: $date\n\n";
    print MAILFILE "Your FAX request could not be granted.\n";
    print MAILFILE "Reason: You didn't specify a FAX number.\n";
    close MAILFILE;

    die ("ERROR: No fax number found\n");
}

###########################################################
# Inform the sender about an empty FAX body
sub EmptyBody {
    # Inform the original sender that the fax is rejected
    open (MAILFILE, "| $MailCmd $MailCmdOptions") || die ("ERROR: Can not notify requestor\n");
    print MAILFILE "From: MAIL2FAX gateway (mail2fax)\n";
    print MAILFILE "To: $From\n";
    print MAILFILE "Subject: Re: Your FAX is rejected\n";
    print MAILFILE "Date: $date\n\n";
    print MAILFILE "Your FAX request could not be granted.\n";
    print MAILFILE "Reason: You didn't submit any lines in the FAX body.\n";
    close MAILFILE;

    die ("ERROR: Empty body\n");
}

###########################################################
# Inform the sender about missing FAX user-ID
sub MissingID {
    # Inform the original sender that the fax is rejected
    open (MAILFILE, "| $MailCmd $MailCmdOptions") || die ("ERROR: Can not notify requestor\n");
    print MAILFILE "From: MAIL2FAX gateway (mail2fax)\n";
    print MAILFILE "To: $From\n";
    print MAILFILE "Subject: Re: Your FAX is rejected\n";
    print MAILFILE "Date: $date\n\n";
    print MAILFILE "Your FAX request to $FaxNo could not be granted.\n";
    print MAILFILE "Reason: You didn't specify a FAX user.\n";
    close MAILFILE;

    die ("ERROR: No user found\n");
}

###########################################################
# Inform the sender that the user-ID is unknown
sub UnknownUser {
    # Inform the original sender that the fax is rejected
    open (MAILFILE, "| $MailCmd $MailCmdOptions") || die ("ERROR: Can not notify requestor\n");
    print MAILFILE "From: MAIL2FAX gateway (mail2fax)\n";
    print MAILFILE "To: $From\n";
    print MAILFILE "Subject: Re: Your FAX is rejected\n";
    print MAILFILE "Date: $date\n\n";
    print MAILFILE "Your FAX request to $FaxNo could not be granted.\n";
    print MAILFILE "Reason: The specified FAX user $FaxUser is unknown.\n";
    close MAILFILE;

    die ("ERROR: Fax user unknown\n");
}

###########################################################
# Inform the sender about missing FAX password
sub MissingPass {
    # Inform the original sender that the fax is rejected
    open (MAILFILE, "| $MailCmd $MailCmdOptions") || die ("ERROR: Can not notify requestor\n");
    print MAILFILE "From: MAIL2FAX gateway (mail2fax)\n";
    print MAILFILE "To: $From\n";
    print MAILFILE "Subject: Re: Your FAX is rejected\n";
    print MAILFILE "Date: $date\n\n";
    print MAILFILE "Your FAX request to $FaxNo could not be granted.\n";
    print MAILFILE "Reason: You didn't specify a FAX password.\n";
    close MAILFILE;

    die ("ERROR: No password found\n");
}

###########################################################
# Inform the sender that the password is unknown
sub IncorrectPass {
    # Inform the original sender that the fax is rejected
    open (MAILFILE, "| $MailCmd $MailCmdOptions") || die ("ERROR: Can not notify requestor\n");
    print MAILFILE "From: MAIL2FAX gateway (mail2fax)\n";
    print MAILFILE "To: $From\n";
    print MAILFILE "Subject: Re: Your FAX is rejected\n";
    print MAILFILE "Date: $date\n\n";
    print MAILFILE "Your FAX request to $FaxNo could not be granted.\n";
    print MAILFILE "Reason: The specified FAX password is incorrect.\n";
    close MAILFILE;

    die ("ERROR: Fax password incorrect\n");
}

###########################################################
# Inform the sender that not enough credits are left
sub InsufficientCredits {
    # Inform the original sender that the fax is rejected
    open (MAILFILE, "| $MailCmd $MailCmdOptions") || die ("ERROR: Can not notify requestor\n");
    print MAILFILE "From: MAIL2FAX gateway (mail2fax)\n";
    print MAILFILE "Cc: $FaxAdmin\n";
    print MAILFILE "To: $From\n";
    print MAILFILE "Subject: Re: Your FAX is rejected\n";
    print MAILFILE "Date: $date\n\n";
    print MAILFILE "Your FAX request to $FaxNo could not be granted.\n";
    print MAILFILE "Reason: Your credits are not sufficient.\n";
    print MAILFILE "The cost for this FAX is $FaxCost units, the current balance is $UserCredit{$FaxUser} units.\n";
    close MAILFILE;

    die ("ERROR: Not enough credits\n");
}

###########################################################
# Extract the configuration infos
sub ExtractConf {
    local ($Entry, $Item1, $Item2, $Item3, $Item4, $Item5);

    foreach $Entry (@ConfEntries) {
        # Process only non-comment lines
        next if ($Entry =~ /^\s+#|^#/);

        ($Item1, $Item2, $Item3, $Item4, $Item5) = split (/\s+/, $Entry);
        if ($Item1 =~ "^=FaxSpool=") {
            $FaxSpool = $Item2;
            $FaxSpoolOptions = $Item3 . " " . $Item4 . " " .$Item5;
        } elsif ($Item1 =~ "^=Mailer=") {
            $MailCmd = $Item2;
            $MailCmdOptions = $Item3 . " " . $Item4 . " " .$Item5;
        } elsif ($Item1 =~ "^=Billing=") {
            $Billing = $Item2;
        } elsif ($Item1 =~ "^=Debug=") {
            $Debug = $Item2;
        } elsif ($Item1 =~ "^=Unknown=") {
            $Unknown = $Item2;
        } elsif ($Item1 =~ "^=FaxAdmin=") {
            $FaxAdmin = $Item2;
        } elsif ($Item1 =~ "^=Zone=") {

            # We have an entry for a zone
            $ZonePrefix{$Item1} = $Item2;
            $ZoneCost{$Item1} = $Item3;
        } elsif ($Item1 =~ "^=User=") {

            # We have a user entry
            $UserName{$Item2} = $Item2;
            $UserPass{$Item2} = $Item3;
            $UserDiscount{$Item2} = $Item4;
            $UserCredit{$Item2} = $Item5;
        }
    }

    # Check whether the executables are there and executable
    die ("ERROR: $MailCmd not found") if (! -x $MailCmd);
    die ("ERROR: $FaxSpool not found") if (! -x $FaxSpool);
}

###########################################################
# Parse the mail message
sub ParseMail {
    local ($InMailHeader, $Line, $InFaxHeader, $Temp);

    $InMailHeader = 1;
    foreach $Line (@OriginalMail) {

        # Check header lines
        if ($InMailHeader) {

            # Check for the end of the mail headers
            if ($Line eq "") {

                # Check whether we have a valid return address
                $From = $ReplyTo if ($ReplyTo);
                die ("ERROR: No sender address found\n")
                                        if (($From eq "") && ($ReplyTo eq ""));

                # We are no longer in the mail header
                $InMailHeader = 0;

                # But in the FAX header
                $InFaxHeader = 1;

            # We are still in the mail headers
            } elsif ($Line =~ /^From: /) {
                # Check for a "^From: " header
                ($Temp, $From) = split (/From: /, $Line);
            } elsif ($Line =~ /^Reply-To: /) {
                # Check for a "Reply-To: " header
                ($Temp, $ReplyTo) = split (/^Reply-To: /, $Line);
            }
        } else {

            # We are past the mail headers
            if ($InFaxHeader) {

                # We are in the FAX headers - check for the start of the FAX body
                if ($Line eq "") {

                    # We are no longer in the FAX header portion
                    $InFaxHeader = 0;
                # We are still in the headers - extract the infos
                } elsif ($Line =~ /^Fax-No: /) {
                    ($Temp, $FaxNo) = split (/^Fax-No: /, $Line);
                } elsif ($Line =~ /Fax-To: /) {
                    ($Temp, $FaxTo) = split (/^Fax-To: /, $Line);
                } elsif ($Line =~ /Fax-User: /) {
                    ($Temp, $FaxUser) = split (/^Fax-User: /, $Line);
                } elsif ($Line =~ /Fax-Pass: /) {
                    ($Temp, $FaxPass) = split (/^Fax-Pass: /, $Line);
                }            
            } else {

                # We are in the FAX body - check for the start of the signature
                last if ($Line =~ /^--/);

                $Body[$BodyIndex] = $Line . "\n";
                $BodyIndex++;
            }   # end if $InFaxHeader
        }   # end if $InMailHeader
    }
}
###########################################################
# Calculate the cost for this FAX
sub CalculateFaxCost {

    # The FAX costs at least what a local call costs
    $FaxNormalCost = $ZoneCost{"=Zone=1"};

    # Check whether we have a zone prefix
    if ($FaxNo =~ ("^" . $ZonePrefix{"=Zone=2"}))
    {
        $FaxNormalCost = $ZoneCost{"=Zone=1"};
    } elsif ($FaxNo =~ ("^" . $ZonePrefix{"=Zone=3"}))
    {
        $FaxNormalCost = $ZoneCost{"=Zone=3"};
    } elsif ($FaxNo =~ ("^" . $ZonePrefix{"=Zone=4"}))
    {
        $FaxNormalCost = $ZoneCost{"=Zone=4"};
    } elsif ($FaxNo =~ ("^" . $ZonePrefix{"=Zone=5"}))
    {
        $FaxNormalCost = $ZoneCost{"=Zone=5"};
    } elsif ($FaxNo =~ ("^" . $ZonePrefix{"=Zone=6"}))
    {
        $FaxNormalCost = $ZoneCost{"=Zone=6"};
    }

    # Multiply the cost by the discount factor for this user
    $FaxCost = $FaxNormalCost * $UserDiscount{$FaxUser};
}

###########################################################
# main function

# Get the input
@OriginalMail = <>;
chop (@OriginalMail);

# Get the configuration
open (CF, $ConfFile) || die ("ERROR: Could not find $ConfFile");
@ConfEntries = <CF>;
chop (@ConfEntries);
close (CF);
&ExtractConf;


# Let the actual work be done by a child process
if (fork) {
    exit 0;
}

#----------------------------------------------------------
# NOW WE ARE THE CHILD

# Preset some variables
$From = "";         # mandatory
$ReplyTo = "";      # optional
$FaxNo = "";        # mandatory
$FaxTo = "";        # optional, but nice to have
$FaxUser = "";      # mandatory
$FaxPass = "";      # mandatory
$FaxCost = 0;       # cost for this FAX
$date = `date`;
chop ($date);       # Local date and time
$BodyIndex = 0;     # Number of lines in body
$FaxAdmin = "faxadmin";

# Parse the mail
&ParseMail;

# Do we have a fax number (at least) ?
&MissingNo if ($FaxNo eq "");

# Do we have any lines in the body ?
&EmptyBody if ($BodyIndex == 0);

# Do we have a user-ID ?
&MissingID if ($FaxUser eq "");

# Check the user-ID against the user entries
&UnknownUser if ($UserPass{$FaxUser} eq "");

# Do we have a password ?
&MissingPass if ($FaxPass eq "");
# Check the password against the user entries
&IncorrectPass if ($UserPass{$FaxUser} ne $FaxPass);

# Extract digits from fax number
$FaxNo =~ tr/A-z`~!@#$%^&*()_=+\\|[{}];:'",<>.\/?-//d;

if ($Billing) {
    # Determine the cost of this FAX
    &CalculateFaxCost;

    # Check whether the user has enough credits left
    &InsufficientCredits if ($FaxCost > $UserCredit{$FaxUser});

    # Subtract the cost for this FAX from the remaining credits
    $UserCredit{$FaxUser} -= $FaxCost;
}

# Write the file with the body of the FAX
open (TEMPFILE, "> /tmp/mail2fax.$$.t") || die ("ERROR: Can not create temporary file\n");
print TEMPFILE @Body;
close (TEMPFILE);

# Feed the temporary file into the FAX system
$FaxTo=$Unknown if ($FaxTo eq "");
$FaxSendCmd = sprintf ("%s -D \'%s\' -f \'%s\' %s /tmp/mail2fax.$$.t",
                       $FaxSpool, $FaxTo, $From, $FaxNo);
if ($Debug) {
    print "$FaxSendCmd\n";
    $FaxResult = 0;
} else {
    $FaxResult = system ("$FaxSendCmd");
    if (! $FaxResult) {
        # Successful -> We don't need the temp file anymore ...
        unlink ("/tmp/mail2fax.$$.t");
    }
}

# Inform the original sender that the fax has been spooled
open (MAILFILE, "| $MailCmd $MailCmdOptions") || die ("ERROR: Can not notify requestor\n");
print MAILFILE "From: MAIL2FAX gateway (mail2fax)\n";
print MAILFILE "To: $From\n";
print MAILFILE "Date: $date\n";
if ($FaxResult) {
    print MAILFILE "Subject: Re: Your FAX could not be spooled\n\n";
    print MAILFILE "An internal error occurred while trying to spool the FAX.\n\n";
} else {
    print MAILFILE "Subject: Re: Your FAX is spooled\n\n";
    print MAILFILE "Your FAX request has been granted and the FAX itself is in the send queue.\n\n";
    print MAILFILE "The FAX will be send to $FaxNo.\n";
    print MAILFILE "The FAX recipient is $FaxTo.\n\n" if ($FaxTo);
    if ($Billing) {
        print MAILFILE "The cost for this FAX is $FaxCost units, the remaining balance is $UserCredit{$FaxUser} units.\n";
        $FaxCostDiff = $FaxNormalCost - $FaxCost;
        print MAILFILE "As a preferred customer you saved $FaxCostDiff units.\n" if ($FaxCostDiff);
        print MAILFILE "\n";
    }
}
if ($Debug) {
    print MAILFILE "The exact command to spool the FAX on the local system was:\n";
    print MAILFILE "$FaxSendCmd\n\n";
}
print MAILFILE "Thank you for using the Mail to FAX gateway.\n";
close MAILFILE;

if (($Billing) && ($FaxResult == 0)) {
    # Update the configuration file
    open (CF, "> $ConfFile") || die ("ERROR: Could not find $ConfFile");

    print CF "#####################################################################\n";
    print CF "# mail2fax.rc - configuration file for mail2fax.pl\n";
    print CF "# Last updated: $date\n";
    print CF "# By: $ProgName, Version $Version\n";
    print CF "#--------------------------------------------------------------------\n";
    print CF "# Format:\n";
    print CF "#   Any line starting with '#' is a comment\n";
    print CF "#   All legal entries have three items separated by a space(s)\n";
    print CF "#   Several sections (see below for explanation)\n";
    print CF "#====================================================================\n";
    print CF "# The program to spool a FAX\n";
    print CF "# It has to accept a recipient via an option '-D', the sender via\n";
    print CF "#  an option '-f', then the fax number and lastly the fax text as\n";
    print CF "#  arguments.\n";
    print CF "=FaxSpool=  $FaxSpool $FaxSpoolOptions\n";
    print CF "#====================================================================\n";
    print CF "# The command to send a mail with.\n";
    print CF "# It has to expect a complete mail message at it's standard input.\n";
    print CF "=Mailer=    $MailCmd $MailCmdOptions\n";    
    print CF "#====================================================================\n";
    print CF "# The billing option\n";
    print CF "# By default this is on, a value of 0 disables it\n";
    print CF "=Billing=   $Billing\n";    
    print CF "#====================================================================\n";
    print CF "# The debug option\n";
    print CF "# By default this is off, any value >0 enables it\n";
    print CF "=Debug=     $Debug\n";
    print CF "#====================================================================\n";
    print CF "# The name for an unknown recipient\n";
    print CF "# By default this is \"unknown\"\n";
    print CF "=Unknown=   $Unknown\n";
    print CF "#====================================================================\n";
    print CF "# The FAX administrator\n";
    print CF "# By default this is faxadmin\n";
    print CF "=FaxAdmin=  $FaxAdmin\n";
    print CF "#====================================================================\n";
    print CF "# The phone zones for billing purposes\n";
    print CF "# The cheapest is 1, the most expensive one is 6\n";
    print CF "# Each zone defines the phone number prefix and the price per FAX in\n";
    print CF "#  1/100 of the currency\n";
    print CF "# Zone 1 - local calls (no special prefix)\n";
    print CF "# Zone 2 - calls within the same area code (long-distance within LATA)\n";
    print CF "# Zone 3 - calls to adjacent area code (often same price as LATA)\n";
    print CF "# Zone 4 - calls to area codes in the state\n";
    print CF "# Zone 5 - calls to area codes out-of-state\n";
    print CF "# Zone 6 - calls out of the country\n";
    print CF "=Zone=1   $ZonePrefix{'=Zone=1'}  $ZoneCost{'=Zone=1'}\n";
    print CF "=Zone=2   $ZonePrefix{'=Zone=2'}  $ZoneCost{'=Zone=2'}\n";
    print CF "=Zone=3   $ZonePrefix{'=Zone=3'}  $ZoneCost{'=Zone=3'}\n";
    print CF "=Zone=4   $ZonePrefix{'=Zone=4'}  $ZoneCost{'=Zone=4'}\n";
    print CF "=Zone=5   $ZonePrefix{'=Zone=5'}  $ZoneCost{'=Zone=5'}\n";
    print CF "=Zone=6   $ZonePrefix{'=Zone=6'}  $ZoneCost{'=Zone=6'}\n";
    print CF "#====================================================================\n";
    print CF "# The user list\n";
    print CF "# Each entry consists of the user-ID, the password, a discount factor,\n";
    print CF "#  and the remaining credits in 1/100 of the currency\n";
    foreach $User (keys %UserName) {
        print CF "=User=  $User  $UserPass{$User}  $UserDiscount{$User}   $UserCredit{$User}\n";
    }
    print CF "#====================================================================\n";
    close (CF);
}

exit 0;
