# XYListbox.pm
#
# provide two kinds of ScrolledListboxes, one with one Scrollbar to the
# right (YListbox), and one with one to the right and below (XYListbox).
#
# Creating the Listboxes is done with $lb = $top->[X]YListbox(options);
# Manipulating the structures is done with:
#   $lb->{Frame}->...			# for the frame
#   $lb->{Scrollbar}->...		# for the scrollbar in YListbox
#   $lb->...				# for the listbox
#   $lb->{XScrollbar}->...		# the horizontal SB in XYListbox
#   $lb->{YScrollbar}->...		# the vertical SB in XYListbox
#
# Gert Doering, gert@greenie.muc.de
#

package Tk::XYListbox;

#sub ClassInit 
#{ 
# my ($class,$mw) = @_;
# return $class;
# 

@ISA = qw(Tk::Composite Tk::Listbox);

use Tk::Widget qw(Frame Listbox Scrollbar);

(bless \qw(YListbox))->WidgetClass;


sub new 
{
 my $package = shift;
 my $class   = $package;
 $class =~ s/^Tk:://;
 my $parent = shift;
 $package->DoInit($parent);
 my $f = $parent->Frame();
 my $l = $f->Listbox(@_);
 my $s = $f->Scrollbar("-orient" => "vertical", "-command" => [ "yview", $l ]);
 $l->configure("-yscrollcommand" => ["set", $s]);
 $s->pack("-side" => "right", "-fill" => "y");
 $l->pack("-side" => "left", "-fill" => "both", "-expand" => "y");
 $l->{Frame} = $f;
 $l->{Scrollbar} = $s;
 return bless $l,$package;
}

sub pack
{my $l = shift;
 my $f = $l->{Frame};
 $f->pack(@_);
}

1;

#
# same, but with two scrollbars
#
package Tk::XYListbox; @ISA = qw(Tk::Composite Tk::Listbox);

use Tk::Widget qw(Frame Listbox Scrollbar);

(bless \qw(XYListbox))->WidgetClass;


sub new 
{
 my $package = shift;
 my $class   = $package;
 $class =~ s/^Tk:://;
 my $parent = shift;
 $package->DoInit($parent);
 my $f = $parent->Frame();
 my $l = $f->Listbox(@_);
 my $sv= $f->Scrollbar("-orient" =>"vertical",  "-command" => [ "yview", $l ]);
 my $sh= $f->Scrollbar("-orient" =>"horizontal","-command" => [ "xview", $l ]);
 $l->configure("-yscrollcommand" => ["set", $sv]);
 $l->configure("-xscrollcommand" => ["set", $sh]);
 $sv->pack("-side" => "right", "-fill" => "y");
 $sh->pack("-side" => "bottom", "-fill" => "x");
 $l->pack("-side" => "left", "-fill" => "both", "-expand" => "y");
 $l->{Frame} = $f;
 $l->{YScrollbar} = $sv;
 $l->{XScrollbar} = $sh;
 return bless $l,$package;
}

sub pack
{my $l = shift;
 my $f = $l->{Frame};
 $f->pack(@_);
}

1;
