<?php
namespace Blimp\Security;

use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\Event\GetResponseForExceptionEvent;
use Blimp\Http\BlimpHttpException;
use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\HttpFoundation\Response;

class HttpEventSubscriber implements EventSubscriberInterface {
    private $api;

    public function __construct($api) {
        $this->api = $api;
    }

    public static function getSubscribedEvents() {
        return array(
            'kernel.exception' => array('onKernelException', 100)
        );
    }

    public function onKernelException(GetResponseForExceptionEvent $event) {
        $e = $event->getException();

        $error = null;
        // TODO Make realm app specific
        $details = ['realm' => 'blimp'];

        if ($e instanceof AuthenticationCredentialsNotFoundException) {
            $code = Response::HTTP_BAD_REQUEST;

            $error = 'invalid_request';
            $details['error_description'] = 'No authentication credentials were found.';
        } else if ($e instanceof BadCredentialsException) {
            $code = Response::HTTP_UNAUTHORIZED;

            $error = 'invalid_token';
            $details['error_description'] = 'The access token is invalid.';
        } else if ($e instanceof CredentialsExpiredException) {
            $code = Response::HTTP_UNAUTHORIZED;

            $error = 'invalid_token';
            $details['error_description'] = 'The access token is expired.';
        } else if ($e instanceof AccessDeniedException) {
            $code = Response::HTTP_FORBIDDEN;

            $token = $this->api['security']->getToken();
            if(get_class($token) == 'Blimp\\Security\\Authentication\\BlimpToken') {
                $error = 'insufficient_scope';
                $details['error_description'] = 'The access token has insufficient privileges.';
                $details['scope'] = $e->getMessage();
            }
        } else {
            return;
        }

        $challenge = 'Bearer realm:"'.$details['realm'].'"';
        if(!empty($error)) {
            $challenge .= ',error="'.$error.'"';

            if(!empty($details['error_description'])) {
                $challenge .= ',error_description="'.$details['error_description'].'"';
            }

            if(!empty($details['scope'])) {
                $challenge .= ',scope="'.$details['scope'].'"';
            }
        }

        $event->setException(new BlimpHttpException($code, $error, $details, $e, array('WWW-Authenticate' => $challenge)));
    }
}

/*
    invalid_request
        The request is missing a required parameter, includes an unsupported parameter or parameter value,
        repeats the same parameter, uses more than one method for including an access token,
        or is otherwise malformed.
        The resource server SHOULD respond with the HTTP 400 (Bad Request) status code.
    invalid_token
        The access token provided is expired, revoked, malformed, or invalid for other reasons.
        The resource SHOULD respond with the HTTP 401 (Unauthorized) status code.
        The client MAY request a new access token and retry the protected resource request.
    insufficient_scope
        The request requires higher privileges than provided by the access token.
        The resource server SHOULD respond with the HTTP 403 (Forbidden) status code and MAY include
        the scope attribute with the scope necessary to access the protected resource.

    If the request lacks any authentication information (e.g., the client was unaware that authentication
    is necessary or attempted using an unsupported authentication method), the resource server SHOULD NOT
    include an error code or other error information.
*/
