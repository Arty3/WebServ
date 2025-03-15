#!/usr/bin/env perl

use strict;
use warnings;
use CGI;

my $cgi = CGI->new;

print $cgi->header('text/html; charset=UTF-8');

print "<html><body>";
print "<h1>Perl CGI Test</h1>";

print "<h2>Server Variables:</h2>";
print "<pre>";
foreach my $key (sort keys %ENV)
    print "$key: $ENV{$key}\n";
print "</pre>";

print "<h2>GET Data:</h2>";
print "<pre>";
my %params = $cgi->Vars;
foreach my $key (sort keys %params)
    if ($cgi->param($key) && !$cgi->upload($key))
        print "$key: " . $cgi->param($key) . "\n";
print "</pre>";

print "<h2>POST Data:</h2>";
print "<pre>";
if ($ENV{'REQUEST_METHOD'} eq 'POST')
    my %post_params = $cgi->Vars;
    foreach my $key (sort keys %post_params)
        if ($cgi->param($key) && !$cgi->upload($key))
            if ($cgi->request_method() eq 'POST')
                print "$key: " . $cgi->param($key) . "\n";
else
    print "No POST data available.\n";
print "</pre>";

print "</body></html>";
