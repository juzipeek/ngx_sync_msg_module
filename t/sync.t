use warnings;
use strict;

use Test::More;
use Time::Local;

BEGIN { use FindBin; chdir($FindBin::Bin); }


use lib 'lib';
use File::Path;
use Test::Nginx;


my $NGINX = defined $ENV{TEST_NGINX_BINARY} ? $ENV{TEST_NGINX_BINARY}
        : '../nginx/objs/nginx';
my $t = Test::Nginx->new()->plan(5);

sub mhttp_get($;$;$;%) {
    my ($url, $port, %extra) = @_;
    return mhttp(<<EOF, $port, %extra);
GET $url HTTP/1.0
Host: localhost

EOF
}

sub mrun($;$) {
    my ($self, $conf) = @_;

    my $testdir = $self->{_testdir};

    if (defined $conf) {
        my $c = `cat $conf`;
        $self->write_file_expand('nginx.conf', $c);
    }

    my $pid = fork();
    die "Unable to fork(): $!\n" unless defined $pid;

    if ($pid == 0) {
        my @globals = $self->{_test_globals} ?
            () : ('-g', "pid $testdir/nginx.pid; "
                  . "error_log $testdir/error.log debug;");
        exec($NGINX, '-c', "$testdir/nginx.conf", '-p', "$testdir",
             @globals) or die "Unable to exec(): $!\n";
    }

    # wait for nginx to start

    $self->waitforfile("$testdir/nginx.pid")
        or die "Can't start nginx";

    $self->{_started} = 1;
    return $self;
}

###############################################################################

select STDERR;

warn "your test dir is ".$t->testdir();

$t->write_file_expand('nginx.conf', <<'EOF');

%%TEST_GLOBALS%%

daemon off;
worker_processes 2;

events {
    accept_mutex off;
}

http {
    %%TEST_GLOBALS_HTTP%%

    server {
        listen 8088;
        location / {
            sync_msg_demo;
        }
    }
}

EOF

mrun($t);

###############################################################################

like(mhttp_get('/', 8088), qr/sync_msg_demo/, 'sync_msg_demo');
like(mhttp_get('/test', 8088), qr/test/, 'set test');
like(mhttp_get('/', 8088), qr/test/m, 'test1');
like(mhttp_get('/', 8088), qr/test/m, 'test2');
like(mhttp_get('/', 8088), qr/test/m, 'test3');

$t->stop();

##############################################################################


sub mhttp($;$;%) {
    my ($request, $port, %extra) = @_;
    my $reply;
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        local $SIG{PIPE} = sub { die "sigpipe\n" };
        alarm(2);
        my $s = IO::Socket::INET->new(
            Proto => "tcp",
            PeerAddr => "127.0.0.1:$port"
            );
        log_out($request);
        $s->print($request);
        local $/;
        select undef, undef, undef, $extra{sleep} if $extra{sleep};
        return '' if $extra{aborted};
        $reply = $s->getline();
        alarm(0);
    };
    alarm(0);
    if ($@) {
        log_in("died: $@");
        return undef;
    }
    log_in($reply);
    return $reply;
}
