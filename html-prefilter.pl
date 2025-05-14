#!/usr/bin/perl -w

while (<STDIN>) {
    # Extra HTML to insert after <head>
    if ( $_ =~ m/<head>/ ) {
        print <<EOF
<head>
<style>
    body {
        font-family: Arial,Sans;
    }
</style>
<table><tr>
    <td style="font-size:30px; font-weight:bold;" width=1%  align=center>$ARGV[0](8)</td>
    <td style="font-size:30px; font-weight:bold;" width=50% align=center>Small Simple SMTP Mail Server</td>
    <td style="font-size:30px; font-weight:bold;" width=1%  align=center>$ARGV[0](8)</td>
</tr></table>
EOF
;
    } else {
        print($_);
    }
}
