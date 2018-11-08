#!/usr/bin/perl -T -w

$ENV{PATH} = "/bin";

use strict;
use warnings;
use feature qw(say);

use Getopt::Std;
use HTTP::Daemon;
use URI;
use URI::QueryParam;
use Path::Iterator::Rule;
use File::Basename;

my $host = '127.0.0.1';
my $port = 19181;
my $tmp = '/tmp';
my $path = '/var/cache/nfdump';
my $mtime = 600;
my $maxn = 10;
my $maxnph = 2;

my %opts;

getopts ( 'p:t:d:', \%opts ) or abort ();

if ( defined $opts{p} ) { $port = $opts{p}; }

if ( defined $opts{t} ) { $tmp = $opts{t}; }

if ( defined $opts{d} ) { $path = $opts{d}; }

if ( not -w $tmp ) { die "directory $tmp not writeable\n"; }

if ( not -d $path ) { die "directory $path does not exist\n"; }

my $d = HTTP::Daemon->new ( Proto => "tcp", Blocking => 1, Reuse => 1, LocalAddr => $host, LocalPort => $port ) || die;

print "Please contact me at: <URL:", $d->url, ">\n";

while ( my $c = $d->accept )
{
	while ( my $r = $c->get_request )
	{
		if ( $r->method eq 'GET' and $r->uri->path eq "/nfdump" )
		{
			my $n = 0;

			my $u = URI->new ( $r->uri );

			my $get_regex = $u->query_param ( 'regex' );
			my $get_mtime = $u->query_param ( 'mtime' );
			my $get_maxn = $u->query_param ( 'maxn' );
			my $get_maxnph = $u->query_param ( 'maxnph' );

			if ( $get_mtime && $get_mtime =~ /^[0-9]+$/ )
			{
				$mtime = $get_mtime;
			}

			if ( $get_maxn && $get_maxn =~ /^[0-9]+$/ )
			{
				$maxn = $get_maxn;
			}

			if ( $get_maxnph && $get_maxnph =~ /^[0-9]+$/ )
			{
				$maxnph = $get_maxnph;
			}

			my $amount = ( time - $mtime );

			my $drule = Path::Iterator::Rule->new;

			$drule->min_depth ( 1 );
			$drule->max_depth ( 1 );
			$drule->directory;

			if ( $get_regex )
			{
				$drule->name ( qr/($get_regex)$/mp );
			}

			my $dit = $drule->iter( $path );

			my $output;

			while ( my $dir = $dit->() )
			{
				my $nph = 0;
				my $basename = basename ( $dir );
				my $frule = Path::Iterator::Rule->new;

				my ($safe_basename) = $basename =~ /^([A-z0-9.]+)$/;

				$frule->min_depth ( 4 );
				$frule->max_depth ( 4 );
				$frule->size ( ">1k" );
				$frule->mtime ( ">$amount" );
				$frule->name ( "nfcapd.2*" );
				$frule->file;

				my $fit = $frule->iter( $dir );

				while ( my $file = $fit->() )
				{
					my ($safe_file) = $file =~ /^([-\@:\/\\\w.]+)$/;

					if ( $n < $maxn && $nph < $maxnph )
					{
						my $last = 0;

						my $tmpfile = $tmp . '/' . $safe_basename . '.last';
						my ($safe_tmpfile) = $tmpfile =~ /^([-\@:\/\\\w.]+)$/;

						if ( open ( my $fho, '<', $safe_tmpfile ) )
						{
							$last = <$fho>;
							close ( $fho );
							undef ( $fho );
						}

						my ( $fnm, $fdr, $fx ) = fileparse ( $file, qr/[0-9]+$/ );

						if ( $fx > $last )
						{
							say $safe_file;

							$output .= `/usr/bin/nfdump -N -q -o 'fmt:{"host":"$safe_basename","tr":"%tr +03:00","ismc":"%ismc","pr":"%pr","sa":"%sa","sp":"%sp","da":"%da","dp":"%dp","pkt":"%pkt","byt":"%byt","fl":"%fl","ts":"%ts +03:00","te":"%te +03:00","in":"%in","out":"%out","flg":"%flg","nevt":"%nevt"}' -r $safe_file | /bin/sed 's/ *" */"/g'`;

							$n ++;
							$nph ++;

							if ( open ( my $fh, '>', $safe_tmpfile ) )
							{
								print $fh $fx;
								close ( $fh );
								undef ( $fh );
							}
							else
							{
								die;
							}
						}

						undef ( $safe_tmpfile );
						undef ( $tmpfile );
						undef ( $last );
					}

					undef ( $file );
					undef ( $safe_file );
				}

				undef ( $fit );
				undef ( $frule );
				undef ( $dir );
				undef ( $basename );
				undef ( $safe_basename );
				undef ( $nph );
			}


			my $h = HTTP::Headers->new;
			my $rr = HTTP::Response->new( 200, '', ,$h, $output );

			$c->send_response ( $rr );

			undef ( $h );
			undef ( $rr );
			undef ( $output );

			undef ( $drule );
			undef ( $amount );
			undef ( $u );
			undef ( $n );
		}
		else
		{
			$c->send_error( 403 );
		}

		undef ( $r );
	}

	$c->close;

	undef ( $c );
}

undef ( $d );
