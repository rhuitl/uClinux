# Ben Myers <0003571400@mcimail.com>

# Sum up sizes of Windows OBJ files in current directory
# requires DOS 5.0 and Borland TDUMP
# A clumsy script to count Windows OBJs and sum up the CODE sizes
# run with
#       awk -fwinobj.awk work1
# where work1 is a work file
# You must have at least one filename as an arg, else awk will want to read
# from con:, hence the requirement for work1
BEGIN {
# redirection done by shelled command
ocount = 0  # obj module counter
otsize = 0  # text size accumulator
odsize = 0  # data size accumulator
system("del workfile.$%$") # Will probably cause a File Not Found message
# Generate a list of OBJs
system("dir *.obj /b >" ARGV[1])
while (getline < ARGV[1] > 0) {
# TDUMP selects only the SEGDEFs to speed things up a lot
# and keeps on piping to the workfile
system("tdump " $1 " -oiSEGDEF >>workfile.$%$")
ocount++
}
# Now read workfile back, processing lines that are module ids and SEGDEF info
# Print one line for each SEGDEF processed
j = 1
while (getline < "workfile.$%$" > 0) {
# module name
if($1 == "Display" && $2 == "of" && $3 == "File") { module_name = $4 }
# SEGDEF CODE
if($2 == "SEGDEF" && $9 =="'CODE'") {
decval = hexdec($11)
otsize += decval
printf ("%12s CODE %4s %7i\n", module_name, $11, decval)
j++ }
# SEGDEF DATA
if($2 == "SEGDEF" && $9 =="'DATA'") {
decval = hexdec($11)
odsize += decval
printf ("%12s DATA %4s %7i\n", module_name, $11, decval)
j++ }
} # while
} # end of BEGIN section
# no main loop at all!
END {
# print summary and delete work files
printf ("%i OBJ files\n", ocount)
printf ("Total CODE size   %04x %7li bytes\n", otsize, otsize)
printf ("Total DATA size   %04x %7li bytes\n", odsize, odsize)
system("del "ARGV[1])
system("del workfile.$%$")
}  # end of END section

# No scanf in awk, so convert hex string x to decimal the hard way
function hexdec (x) {
result = 0
for (i=1; i<=length(x); i++) {
thechar = substr(x,i,1)
# digits 0-9 and lower case hex produced by TDUMP
# use brute force
if (thechar == "0") {result = result*16}
if (thechar == "1") {result = result*16 + 1}
if (thechar == "2") {result = result*16 + 2}
if (thechar == "3") {result = result*16 + 3}
if (thechar == "4") {result = result*16 + 4}
if (thechar == "5") {result = result*16 + 5}
if (thechar == "6") {result = result*16 + 6}
if (thechar == "7") {result = result*16 + 7}
if (thechar == "8") {result = result*16 + 8}
if (thechar == "9") {result = result*16 + 9}
if (thechar == "a") {result = result*16 + 10}
if (thechar == "b") {result = result*16 + 11}
if (thechar == "c") {result = result*16 + 12}
if (thechar == "d") {result = result*16 + 13}
if (thechar == "e") {result = result*16 + 14}
if (thechar == "f") {result = result*16 + 15}
} # for (i=1;i<length(x);i++)
return result
} # function hexdec (x)

