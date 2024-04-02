package Net::EPP::Server;
# ABSTRACT: A simple EPP server implementation.
use Carp;
use Crypt::OpenSSL::Random;
use Data::Dumper;
use DateTime::Format::ISO8601;
use Digest::SHA qw(sha512_hex);
use IO::Socket::SSL;
use List::Util qw(any none);
use Mozilla::CA;
use Net::EPP::Frame;
use Net::EPP::Protocol;
use Net::EPP::ResponseCodes;
use Sys::Hostname;
use XML::LibXML;
use base qw(Net::Server::PreFork);
use bytes;
use utf8;
use open qw(:encoding(utf8));
use feature qw(state);
use strict;
use warnings;

=pod

=head1 SYNOPSIS

    use Net::EPP::Server;
    use Net::EPP::ResponseCodes;

    # these are the objects we want to support
    my @OBJECTS = qw(domain host contact);

    my @EXTENSIONS = qw(secDNS rgp loginSec allocationToken launch);

    #
    # You can pass any arguments supported by Net::Server::Proto::SSL, but
    # by default the server will listen on localhost port 7000 using a
    # self-signed certificate.
    #
    Net::EPP::Server->new->run(

        #
        # this defines callbacks that will be invoked when an EPP frame is
        # received
        #
        handlers => {
            hello   => \&hello_handler,
            login   => \&login_handler,
            check   => \&check_handler,
            info    => \&info_handler,
            create  => \&create_handler,

            # add more here
        }
    );

    #
    # The <hello> handler is special and just needs
    # to return a hashref containing server metadata.
    #
    sub hello_handler {
        return {
            # this is the server ID and is optional, if not provided the system
            # hostname will be used
            svID => 'epp.example.com',

            # this is optional
            lang => [ qw(en fr de) ],

            # these are arrayrefs of namespace URIs
            objects => [
                map { Net::EPP::Frame::ObjectSpec->xmlns($_) } @OBJECTS
            ],

            extensions => [
                map { Net::EPP::Frame::ObjectSpec->xmlns($_) } @EXTENSIONS
            ],
        };
    }

    #
    # All other handlers work the same. They are passed a hash of arguments and
    # can return a simple result code, a result code and message, or
    # a XML::LibXML::Document object.
    #
    sub login_handler {
        my %args = @_;

        my $frame = $args{'frame'};

        my $clid = $frame->getElementsByTagName('clid')->item(0)->textContent;
        my $pw = $frame->getElementsByTagName('pw')->item(0)->textContent;

        if (!validate_credentials($clid, $pw)) {
            return AUTHENTICATION_FAILED;

        } else {
            return OK;

        }  
    }

=head1 INTRODUCTION

C<Net::EPP::Server> provides a high-level framework for developing L<Extensible
Provisioning Protocol (EPP)|https://www.rfc-editor.org/info/std69> servers.

It implements the TLS/TCP transport described in L<RFC 5734|https://www.rfc-editor.org/info/rfc5734>,
and the L<EPP Server State Machine|https://www.rfc-editor.org/rfc/rfc5730.html#:~:text=Figure%201:%20EPP%20Server%20State%20Machine>
described in Section 2 of L<RFC 5730|https://www.rfc-editor.org/rfc/rfc5730.html>.

=cut

sub new {
    my $package = shift;

    return bless($package->SUPER::new, $package);
}

=pod

=head1 SERVER CONFIGURATION

C<Net::EPP::Server> inherits from L<Net::Server> I<(specifically
L<Net::Server::PreFork>)>, and so the C<run()> method accepts all the parameters
supported by that module, plus the following:

=over * C<handlers>, which is a hashref which maps events (including EPP
commands) to callback functions. See below for details.

=over * C<client_ca_file>, which is the location on disk of a file which can be
use to validate client certificates.

=back

=cut

sub run {
    my ($self, %args) = @_;

    $args{'host'}   ||= 'localhost';
    $args{'port'}   ||= 7000;
    $args{'proto'}  ||= 'ssl';

    $self->{'epp'} = {
        'handlers'          => delete($args{'handlers'}) || {},
        'client_ca_file'    => $args{'client_ca_file'},
    };

    return $self->SUPER::run(%args);
}

#
# This method is called when a new connection is received. It sends the
# <greeting> to the client, then enters the main loop.
#
sub process_request {
    my ($self, $socket) = @_;

    $self->send_frame($socket, $self->generate_greeting);

    $self->main_loop($socket);

    $socket->flush;
    $socket->close;
}

#
# This method initialises the session, and calls main_loop_iteration() in a
# loop. That method returns the result code, and the loop will terminate if the
# code indicates that it should.
#
sub main_loop {
    my ($self, $socket) = @_;

    my $session = {
        'id' => $self->generate_svTRID,
    };

    while (1) {
        my $code = $self->main_loop_iteration($socket, $session);

        last if (OK_BYE == $code || $code >= COMMAND_FAILED_BYE);
    }
}

#
# This method reads a frame from the client, passes it to process_frame(),
# sends the response back to the client, and returns the result code back to
# main_loop().
#
sub main_loop_iteration {
    my ($self, $socket, $session) = @_;

    # TODO - add a timeout
    my $xml = eval { Net::EPP::Protocol->get_frame($socket) };
    return COMMAND_FAILED_BYE if (!$xml);

    my $response = $self->process_frame($xml, $session);

    $self->send_frame($socket, $response);

    if ('greeting' eq $response->documentElement->firstChild->localName) {
        return OK;

    } else {
        return $response->getElementsByTagName('result')->item(0)->getAttribute('code');

    }
}

=pod

=head1 EVENT HANDLERS

You implement the business logic of your EPP server by specifying callbacks that
are invoked for certain events. These come in two flavours: I<events> and
C<commands>.

=head2 C<frame_received>

Called when a frame has been successfully parsed and validated, but before it
has been processed. The input frame will be passed as the C<frame> argument. It
is B<not> called for C<E<lt>helloE<gt>> commands.

=head2 C<response_prepared>

Called when a response has been generated, but before it has been sent back to
the client. The response will be passed as the C<response> argument, while the
input frame will be passed as the C<frame> argument. It is B<not> called for
C<E<lt>helloE<gt>> and C<E<lt>logoutE<gt>>commands.

=head2 C<session_closed>

C<Net::EPP::Server> takes care of handling session management, but this event
handler will be called once a C<E<lt>logoutE<gt>> command has been successfully
processed, but before the client connection has been closed. The C<session>
argument will contain a hashref of the session (see below).

=cut

#
# This method processes an XML frame received from a client and returns a
# response frame. It manages session state, to ensure that clients that haven't
# authenticated yet can't do anything except login.
#
sub process_frame {
    my ($self, $xml, $session) = @_;

    my $svTRID = $self->generate_svTRID;

    my $frame = $self->parse_frame($xml);

    return $self->generate_error(
        code    => SYNTAX_ERROR,
        msg     => 'XML parse error.',
        svTRID  => $svTRID,
    ) unless ($frame->isa('XML::LibXML::Document'));

    return $self->generate_error(
        code    => SYNTAX_ERROR,
        msg     => 'XML schema error.',
        svTRID  => $svTRID,
    ) unless ($self->validate_frame($frame));

    return $self->generate_greeting if ('hello' eq $frame->getElementsByTagName('epp')->item(0)->firstChild->localName);

    eval { $self->run_callback(
        event   => 'frame_received',
        frame   => $frame
    ) };

    my $clTRID = $frame->getElementsByTagName('clTRID')->item(0)->textContent;

    my $command;
    if ('command' eq $frame->documentElement->firstChild->localName) {
        $command = $frame->documentElement->firstChild->firstChild->localName;

    } elsif ('extension' eq $frame->documentElement->firstChild->localName) {
        $command = 'other';

    } else {
        return $self->generate_error(
            code    => SYNTAX_ERROR,
            msg     => 'First child element of <epp> is not <command> or <extension>.',
            clTRID  => $clTRID,
            svTRID  => $svTRID,
        );
    }

    return $self->generate_error(
        code    => AUTHENTICATION_ERROR,
        msg     => 'You are not logged in.',
        clTRID  => $clTRID,
        svTRID  => $svTRID,
    ) if (!defined($session->{'clid'}) && 'login' ne $command);

    return $self->generate_error(
        code    => AUTHENTICATION_ERROR,
        msg     => 'You are already logged in.',
        clTRID  => $clTRID,
        svTRID  => $svTRID,
    ) if (defined($session->{'clid'}) && 'login' eq $command);

    if ('logout' eq $command) {
        eval { $self->run_callback(event => 'session_closed', session => $session) };

        return $self->generate_response(
            code    => OK_BYE,
            msg     => 'Command completed successfully; ending session.',
            clTRID  => $clTRID,
            svTRID  => $svTRID,
        );
    }

    my $response = $self->handle_command(
        command => $command,
        frame   => $frame,
        session => $session,
        clTRID  => $clTRID,
        svTRID  => $svTRID,
    );

    if ('login' eq $command && $response->getElementsByTagName('result')->item(0)->getAttribute('code') < UNKNOWN_COMMAND) {
        $session->{'clid'}          = $frame->getElementsByTagName('clID')->item(0)->textContent;
        $session->{'lang'}          = $frame->getElementsByTagName('lang')->item(0)->textContent;
        $session->{'objects'}       = [ map { $_->textContent } $frame->getElementsByTagName('objURI') ];
        $session->{'extensions'}    = [ map { $_->textContent } $frame->getElementsByTagName('extURI') ];
    }

    eval { $self->run_callback(
        event       => 'response_prepared',
        frame       => $frame,
        response    => $response
    ) };

    return $response;
}

#
# This method invokes the event handler for a given event/command, and passes
# back the response, returning an error if the command references an
# unimplemented command, object service or extension.
#
sub handle_command {
    my $self    = shift;
    my %args    = @_;
    my $command = $args{'command'};
    my $frame   = $args{'frame'};
    my $session = $args{'session'};
    my $clTRID  = $args{'clTRID'};
    my $svTRID  = $args{'svTRID'};

    my $response;

    #
    # check for an unimplemented command
    #
    return $self->generate_error(
        code    => UNIMPLEMENTED_COMMAND,
        msg     => sprintf('This server does not implement the <%s> command.', $command),
        clTRID  => $clTRID,
        svTRID  => $svTRID,
    ) unless (defined($self->{'epp'}->{'handlers'}->{$command}));

    if ('login' ne $command) {
        #
        # check for an unimplemented object
        #
        if (any { $command eq $_ } qw(check info create delete renew transfer update)) {
            my $type = $frame->getElementsByTagName('epp')->item(0)->firstChild->firstChild->firstChild->namespaceURI;

            if (none { $type eq $_ } @{$session->{'objects'}}) {
                return $self->generate_error(
                    code    => UNIMPLEMENTED_OBJECT_SERVICE,
                    msg     => sprintf('This server does not support %s objects.', $type),
                    clTRID  => $clTRID,
                    svTRID  => $svTRID,
                );
            }
        }

        #
        # check for an unimplemented extension
        #
        my $extn = $frame->getElementsByTagName('extension')->item(0);
        if ($extn) {
            use Data::Dumper;
            print STDERR Dumper($session);
            foreach my $el ($extn->childNodes) {
                print STDERR $el->namespaceURI."\n";
                if (none { $el->namespaceURI eq $_ } @{$session->{'extensions'}}) {
                    return $self->generate_error(
                        code    => UNIMPLEMENTED_EXTENSION,
                        msg     => sprintf('This server does not support the %s extension.', $el->namespaceURI),
                        clTRID  => $clTRID,
                        svTRID  => $svTRID,
                    );
                }
            }
        }
    }

    return $self->run_command(%args);
}

=pod

=head2 C<hello>

The C<hello> event handler is called when a new client connects, or a
C<E<lt>helloE<gt>> frame is received.

Unlike the other event handlers, this handler B<MUST> respond with a hashref
which contains the following entries:

=over

=item * C<svID> (OPTIONAL) - the server ID. If not provided, the system hostname
will be used.

=item * C<lang> (OPTIONAL) - an arrayref containing language codes. It not
provided, C<en> will be used as the only supported language.

=item * C<objects> (REQUIRED) - an arrayref of namespace URIs for 

=back

=cut

sub generate_greeting {
    my $self = shift;

    state $hello;

    if (!$hello) {
        $hello = XML::LibXML::Document->new;
        $hello->setDocumentElement($hello->createElementNS($Net::EPP::Frame::EPP_URN, 'epp'));
        $hello->documentElement->appendChild($hello->createElement('hello'));
    }

    my $data = $self->run_callback(event => 'hello', frame => $hello);

    my $frame = XML::LibXML::Document->new;

    $frame->setDocumentElement($frame->createElementNS($Net::EPP::Frame::EPP_URN, 'epp'));
    my $greeting = $frame->documentElement->appendChild($frame->createElement('greeting'));

    $greeting->appendChild($frame->createElement('svID'))->appendText($data->{'svID'} || lc(hostname));
    $greeting->appendChild($frame->createElement('svDate'))->appendText(DateTime->now->strftime('%Y-%m-%dT%H:%M:%S.0Z'));

    my $svcMenu = $greeting->appendChild($frame->createElement('svcMenu'));
    $svcMenu->appendChild($frame->createElement('version'))->appendText('1.0');

    foreach my $lang (@{$data->{'lang'} || [qw(en)]}) {
        $svcMenu->appendChild($frame->createElement('lang'))->appendText($lang);
    }

    foreach my $objURI (@{$data->{'objects'}}) {
        $svcMenu->appendChild($frame->createElement('objURI'))->appendText($objURI);
    }

    if (scalar(@{$data->{'extensions'}}) > 0) {
        my $svcExtension = $svcMenu->appendChild($frame->createElement('svcMenu'));

        foreach my $extURI (@{$data->{'extensions'}}) {
            $svcExtension->appendChild($frame->createElement('extURI'))->appendText($extURI);
        }
    }

    my $dcp = $svcMenu->appendChild($frame->createElement('dcp'));
    $dcp->appendChild($frame->createElement('access'))->appendChild($frame->createElement('all'));
    $dcp->appendChild($frame->createElement('statement'))->appendChild($frame->createElement('purpose'))->appendChild($frame->createElement('prov'));
    $dcp->appendChild($frame->createElement('recipient'))->appendChild($frame->createElement('public'));
    $dcp->appendChild($frame->createElement('retention'))->appendChild($frame->createElement('legal'));

    return $frame;
}

=pod

=head2 COMMAND HANDLERS

The standard EPP command repertoire is:

=over

=item * C<login>

=item * C<logout>

=item * C<poll>

=item * C<check>

=item * C<info>

=item * C<create>

=item * C<delete>

=item * C<renew>

=item * C<transfer>

=item * C<delete>

=back

A command handler may be specified for all of these commands except C<logout>,
since C<Net::EPP::Server> handles this itself.

Since EPP allows the command repertoire to be extended (by omitting the
C<E<lt>commandE<gt>> element and using the C<E<lt>extensionE<gt>> element only),
C<Net::EPP::Server> also supports the C<other> event which will be called when
processing such frames.

All command handlers receive a hash or arguments containing the following:

=over

=item * C<event> - the name of the command.

=item * C<frame> - an L<XML::LibXML::Document> object representing the frame
received from the client.

=item * C<session> - a hashref containing the session information.

=item * C<clTRID> - the value of the C<E<lt>clTRIDE<gt>> element taken from the
frame received from the client.

=item * C<svTRID> - a value suitable for inclusion in the C<E<lt>clTRIDE<gt>>
element of the response.

=back

=head3 SESSION PARAMETERS

As mentioned above, the C<$args{session}> parameter is a hashref which contains
information about the session. It contains the following:

=over

=item * C<clid> - the client ID used to log in

=item * C<lang> - the language specified at login

=item * C<objects> - the object URI(s) specified at login

=item * C<lang> - the extension URI(s) specified at login

=back

=head3 RETURN VALUES

=head4 1. Simple result code

Command handlers can signal the result of a command by simply passing a single
integer value. L<Net::EPP::ResponseCodes> may be used to avoid literal integers.

Example:

    sub delete_handler {
        my %args = @_;

        # business logic here

        if ($success) {
            return OK;

        } else {
            return COMMAND_FAILED;

        }
    }

C<Net::EPP::Server> will construct a standard EPP response frame using the result
code and send it to the client.

=head4 2. Result code + message

If the command handler returns two values, and the first is a valid result code,
then the second can be a message. Example:

    sub delete_handler {
        my %args = @_;

        # business logic here

        if ($success) {
            return (OK, 'object deleted');

        } else {
            return (COMMAND_FAILED, 'object not deleted');

        }
    }

C<Net::EPP::Server> will construct a standard EPP response frame using the result
code and message, and send it to the client.

=head4 3. Result code + XML elements

The command handler may return a result code followed by an array of between
one and three L<XML::LibXML::Element> objects, in any order, representing the
C<E<lt>resDataE<gt>>, C<E<lt>msgQE<gt>> and C<E<lt>extensionE<gt>> elements.
Example:

    sub delete_handler {
        my %args = @_;

        # business logic here

        return (
            OK,
            $resData_element,
            $msgQ_element,
            $extension_element,
        );
    }

C<Net::EPP::Server> will construct a standard EPP response frame using the result
code and supplied elements which will be imported and inserted into the
appropriate positions, and send it to the client.

=head4 4. L<XML::LibXML::Document> object

A return value that is a single L<XML::LibXML::Document> object will be sent
back to the client verbatim.

=head3 EXCEPTIONS

C<Net::EPP::Server> will catch any exceptions thrown by the command handler, will
C<carp($@)>, and then send a C<2400> result code back to the client.

=cut

sub run_command {
    my $self    = shift;
    my %args    = @_;
    my $command = $args{'command'};
    my $frame   = $args{'frame'};
    my $session = $args{'session'};
    my $clTRID  = $args{'clTRID'};
    my $svTRID  = $args{'svTRID'};

    my @result = eval { $self->run_callback(
        event   => $command,
        frame   => $frame,
        session => $session,
        clTRID  => $clTRID,
        svTRID  => $svTRID,
    ) };

    if ($@) {
        carp($@);

        return $self->generate_error(
            code    => COMMAND_FAILED,
            clTRID  => $clTRID,
            svTRID  => $svTRID,
        );
    }

    if (1 == scalar(@result)) {
        my $result = shift(@result);

        if ($result->isa('XML::LibXML::Document')) {
            return $result;

        } elsif (is_error_code($result)) {
            return $self->generate_response(
                code    => $result,
                clTRID  => $clTRID,
                svTRID  => $svTRID,
            );

        } else {
            carp(sprintf('<%s> command handler did not return a result code or an XML document', $command));
            return $self->generate_error(
                code    => COMMAND_FAILED,
                clTRID  => $clTRID,
                svTRID  => $svTRID,
            );

        }

    } elsif (is_error_code($result[0])) {
        my $code = shift(@result);

        if (!ref($result[0])) {
            return $self->generate_response(
                code    => $code,
                msg     => $result[0],
                clTRID  => $clTRID,
                svTRID  => $svTRID,
            );

        } else {
            my $response = $self->generate_response(
                code    => $code,
                clTRID  => $clTRID,
                svTRID  => $svTRID,
            );

            my %els;
            foreach my $el (@result) {
                if (!$el->isa('XML::LibXML::Element')) {
                    # TODO

                } elsif (exists($els{$el->localName})) {
                    # TODO

                } else {
                    $els{$el->localName} = $el;

                }
            }

            my $response_el = $response->getElementsByTagName('response')->item(0);
            foreach my $name (grep { exists($els{$_}) } qw(resData msgQ extension)) {
                $response_el->appendChild($response->importNode($els{$name}));
            }

            return $response;
        }

    } else {
        # TODO

    }
}

=pod

=head1 UTILITY METHODS

=head2 C<generate_response(%args)>

This method returns a L<XML::LibXML::Document> element representing the response
described by C<%args>, which should contain the following:

=over

=item * C<code> (OPTIONAL) - the result code. See L<Net::EPP::ResponseCodes>. If
not provided, C<1000> will be used.

=item * C<msg> - a human-readable error message. If not provided, the string
C<"Command completed successfully."> will be used if C<code> is less than C<2000>,
and C<"Command failed."> if C<code> is C<2000> or higher.

=item * C<clTRID> (OPTIONAL) - the client transaction ID.

=item * C<svTRID> (OPTIONAL) - the server's transaction ID.

=back

=cut

sub generate_response {
    my $self    = shift;
    my %args    = @_;
    my $clTRID  = $args{'clTRID'};
    my $svTRID  = $args{'svTRID'};
    my $code    = $args{'code'} || OK;
    my $msg     = $args{'msg'} || ($code < UNKNOWN_COMMAND ? 'Command completed successfully.' : 'Command failed.');

    my $frame = XML::LibXML::Document->new;

    $frame->setDocumentElement($frame->createElementNS($Net::EPP::Frame::EPP_URN, 'epp'));
    my $response = $frame->documentElement->appendChild($frame->createElement('response'));
    my $result = $response->appendChild($frame->createElement('result'));
    $result->setAttribute('code', $code);
    $result->appendChild($frame->createElement('msg'))->appendText($msg);

    if ($clTRID || $svTRID) {
        my $trID = $response->appendChild($frame->createElement('trID'));
        $trID->appendChild($frame->createElement('clTRID'))->appendText($clTRID) if ($clTRID);
        $trID->appendChild($frame->createElement('svTRID'))->appendText($svTRID) if ($svTRID);
    }

    return $frame;
}

=pod

=head2 C<generate_error(%args)>

This method is identical to C<generate_response()> except the default value for
the C<code> parameter is C<2400>, indicating that the command failed for
unspecified reasons.

=cut

sub generate_error {
    my ($self, %args) = @_;
    $args{'code'} = $args{'code'} || COMMAND_FAILED;
    $args{'msg'} = $args{'msg'} || 'An internal error occurred. Please try again later.';
    return $self->generate_response(%args);
}

=pod

=head2 C<generate_svTRID()>

This method returns a unique string suitable for use in the C<E<lt>svTRIDE<gt>>
and similar elements.

=cut

sub generate_svTRID {
    state $counter = time();

    return substr(sha512_hex(
        pack('Q', ++$counter)
        .chr(0)
        .Crypt::OpenSSL::Random::random_pseudo_bytes(32)
    ), 0, 64);
}

=pod

=head2 C<parse_frame($xml)>

Attempts to parse C<$xml> and returns a L<XML::LibXML::Document> if successful.

=cut

sub parse_frame {
    my ($self, $xml) = @_;

    return XML::LibXML->load_xml(
        string      => $xml,
        no_blanks   => 1,
        no_cdata    => 1,
    );
}

=pod

=head2 C<validate_frame($frame)>

Returns true if C<$frame> can be validated against the XML schema.

=cut

sub validate_frame {
    my ($self, $frame) = @_;

    # TODO

    return 1;
}

sub run_callback {
    my $self = shift;
    my %args = @_;
    my $event = delete($args{'event'});

    my $ref = $self->{'epp'}->{'handlers'}->{$event};

    return &{$ref}(%args) if ($ref);
}

=pod

=head2 C<is_error_code($value)>

Returns true if C<$value> is a recognised EPP result code.

=cut

sub is_error_code {
    my $value = shift;
    return (int($value) >= OK && int($value) <= 2502);
}

sub send_frame {
    my ($self, $socket, $frame) = @_;

    Net::EPP::Protocol->send_frame($socket, $frame->toString(1));
}

1;