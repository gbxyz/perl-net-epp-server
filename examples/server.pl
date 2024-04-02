#!perl
# ABSTRACT: an example EPP server built using Net::EPP::Server
use File::Spec;
use File::Temp;
use IPC::Open3;
use Net::EPP::Frame::ObjectSpec;
use Net::EPP::ResponseCodes;
use Net::EPP::Server;
use Sys::Hostname;
use feature qw(state);
use strict;

my $users = {
    'gavin' => 'foo2bar',
};

my ($key, $cert) = auto_ssl();

my $server = Net::EPP::Server->new;

$server->run(
    'client_ca_file'    => $ARGV[0],
    'SSL_key_file'      => $key,
    'SSL_cert_file'     => $cert,
    'handlers'          => {
        'hello'         => \&hello_handler,
        'login'         => \&login_handler,
        'poll'          => \&poll_handler,
        'check'         => \&check_handler,
        'info'          => \&info_handler,
        'create'        => \&create_handler,
        'update'        => \&update_handler,
        'renew'         => \&renew_handler,
        'delete'        => \&delete_handler,
        'transfer'      => \&transfer_handler,
        'other'         => \&other_handler,
    },
);

sub hello_handler {
    my %args = @_;

    return {
        'svID'          => lc(hostname),
        'lang'          => [ qw(en) ],
        'objects'       => [ map { Net::EPP::Frame::ObjectSpec->xmlns($_) } qw(domain) ],
        'extensions'    => [ map { Net::EPP::Frame::ObjectSpec->xmlns($_) } qw(secDNS rgp loginSec allocationToken launch) ],
    };
}

sub login_handler {
    my %args = @_;
    my $frame = $args{'frame'};

    my $loginSec;

    foreach my $el ($frame->getElementsByTagName('extURI')) {
        if ($el->textContent eq Net::EPP::Frame::ObjectSpec->xmlns('loginSec')) {
            $loginSec = 1;
            last;
        }
    }

    if (!$loginSec || '[LOGIN-SECURITY]' ne $frame->getElementsByTagName('pw')->item(0)->textContent) {
        return $server->generate_error(
            code    => AUTHENTICATION_ERROR,
            msg     => 'The Login Security Extension is mandatory.',
            clTRID  => $args{'clTRID'},
            svTRID  => $args{'svTRID'},
        );
    }

    my %values;

    $values{'clID'} = $frame->getElementsByTagName('clID')->item(0)->textContent;

    foreach my $name (qw(pw newPW)) {
        my $el = $frame->getElementsByTagNameNS(Net::EPP::Frame::ObjectSpec->xmlns('loginSec'), $name)->item(0);
        $values{$name} = $el->textContent if ($el);
    }

    if (exists($values{'newPW'})) {
        return $server->generate_error(
            code    => UNIMPLEMENTED_OPTION,
            msg     => 'Changing password is not currently supported.',
            clTRID  => $args{'clTRID'},
            svTRID  => $args{'svTRID'},
        );
    }

    if ($users->{$values{'clID'}} eq $values{'pw'}) {
        return OK;

    } else {
        return AUTHENTICATION_ERROR;

    }
}

sub info_handler {
    return COMMAND_FAILED;
}

#
# This method dynamically generates a self-signed x509 certificate.
#
sub auto_ssl {
    my $key  = File::Temp::tempnam(File::Spec->tmpdir, 'key_');
    my $cert = File::Temp::tempnam(File::Spec->tmpdir, 'cert_');

    my $pid = open3(undef, undef, undef, qw(openssl req -new -newkey rsa:2048
        -days 7 -nodes -x509 -subj / -keyout), $key, q{-out}, $cert);

    waitpid($pid, 0);

    croak('certificate generation failed') if ($? >> 8 > 0);

    chmod(0400, $key);

    return ($key, $cert);
}
