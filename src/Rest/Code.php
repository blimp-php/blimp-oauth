<?php
namespace Blimp\Security\Rest;

use Blimp\Http\BlimpHttpException;
use Blimp\Security\Documents\ResourceOwnerActivity;
use Pimple\Container;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Code {
    protected $api;

    public function process(Container $api, Request $request) {
        $this->api = $api;

        $data = $request->attributes->get('data');

        // inputs
        if (array_key_exists('client_id', $data)) {
            $client_id = $data['client_id'];
        }
        if (array_key_exists('client_secret', $data)) {
            $client_secret = $data['client_secret'];
        }
        if (array_key_exists('redirect_uri', $data)) {
            $redirect_uri = $data['redirect_uri'];
        }

        if (array_key_exists('access_token', $data)) {
            /* user auth with access_token */
            $auth_type = 'access_token';
            $access_token = $data['access_token'];
        } else {
            /* user auth with password */
            $auth_type = 'password';

            if (array_key_exists('username', $data)) {
                $username = $data['username'];
            }
            if (array_key_exists('password', $data)) {
                $password = $data['password'];
            }
            if (array_key_exists('scope', $data)) {
                $scope = $data['scope'];
            }
        }

        $client = null;
        $owner = null;

        $error_code = Response::HTTP_OK;
        $error = '';
        $error_description = '';

        try {
            switch ($request->getMethod()) {
                case 'POST':
                    $real_client_id;
                    $real_client_secret;

                    $authorization_header = null;
                    if ($request->headers->has('authorization')) {
                        $authorization_header = $auth = $request->headers->get('authorization');
                    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
                        $authorization_header = $_SERVER['HTTP_AUTHORIZATION'];
                    } else if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
                        $authorization_header = $_SERVER['PHP_AUTH_DIGEST'];
                    }

                    if ($authorization_header !== null) {
                        if (!empty($client_id) || !empty($client_secret)) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_request';
                            $error_description = 'The request utilizes more than one mechanism for authenticating the client.';
                            break;
                        }

                        if (strpos($authorization_header, 'Basic') === 0) {
                            $real_client_id = $request->headers->get('PHP_AUTH_USER');
                            $real_client_secret = $request->headers->get('PHP_AUTH_PW');

                            if (empty($real_client_id) || empty($real_client_secret)) {
                                $error_code = Response::HTTP_UNAUTHORIZED;
                                $error = 'invalid_client';
                                $error_description = 'Invalid client authentication.';
                                break;
                            }
                        } else {
                            $error_code = Response::HTTP_UNAUTHORIZED;
                            $error = 'invalid_client';
                            $error_description = 'Unsupported client authentication.';
                            break;
                        }
                    } else {
                        if (empty($client_id)) {
                            $error_code = Response::HTTP_UNAUTHORIZED;
                            $error = 'invalid_client';
                            $error_description = 'No client authentication included.';
                            break;
                        }

                        $real_client_id = $client_id;
                        $real_client_secret = !empty($client_secret) ? $client_secret : '';
                    }

                    $client = $this->api['security.oauth.get_client']($real_client_id);
                    if (empty($client)) {
                        $error_code = Response::HTTP_UNAUTHORIZED;
                        $error = 'invalid_client';
                        $error_description = 'Invalid client_id.';
                        break;
                    }

                    if ($client->getSecret() !== $real_client_secret) {
                        $error_code = Response::HTTP_UNAUTHORIZED;
                        $error = 'invalid_client';
                        $error_description = 'Client authentication failed.';
                        break;
                    }

                    $real_redirect_uri = '';

                    $uris = $client->getRedirectURI();
                    $found = false;
                    if (!empty($redirect_uri)) {
                        foreach ($uris as $uri) {
                            $client_redirecturl = $uri->getUri();
                            if (strpos($redirect_uri, $client_redirecturl) === 0) {
                                $parcial = $uri->getParcial();
                                if ($parcial || $redirect_uri === $client_redirecturl) {
                                    $found = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (!$found) {
                        $error_code = Response::HTTP_BAD_REQUEST;
                        $error = 'invalid_request';
                        $error_description = 'Unauthorized redirect_uri.';
                        break;
                    } else {
                        $real_redirect_uri = $redirect_uri;
                    }

                    $to_process_scope = [];

                    if ($auth_type === 'access_token') {
                        $query_builder = $this->api['dataaccess.mongoodm.documentmanager']()->createQueryBuilder();
                        $query_builder->eagerCursor(true);
                        $query_builder->find('Blimp\Security\Documents\AccessToken');

                        $query_builder->field('_id')->equals($access_token);

                        $query = $query_builder->getQuery();

                        $item = $query->getSingleResult();

                        if ($item != null) {
                            if ($item->getClientId() != $real_client_id) {
                                $error_code = Response::HTTP_BAD_REQUEST;
                                $error = 'invalid_grant';
                                $error_description = 'Invalid resource owner credentials.';
                                break;
                            }

                            if ($item->getExpires() != null && $item->getExpires()->getTimestamp() - time() < 0) {
                                $error_code = Response::HTTP_BAD_REQUEST;
                                $error = 'invalid_grant';
                                $error_description = 'Invalid resource owner credentials.';
                                break;
                            }

                            $real_scope = $item->getScope();
                            $profile = $item->getProfile();
                        } else {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_grant';
                            $error_description = 'Invalid resource owner credentials.';
                            break;
                        }
                    } else if ($auth_type === 'password') {
                        if (empty($username)) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_request';
                            $error_description = 'Missing username parameter.';
                            break;
                        }

                        if (empty($password)) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_request';
                            $error_description = 'Missing password parameter.';
                            break;
                        }

                        $owner = $this->api['security.oauth.get_resource_owner']($username, $password);

                        if (empty($owner)) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_grant';
                            $error_description = 'Invalid resource owner credentials.';
                            break;
                        }

                        $profile = $owner->getProfile();

                        if (!empty($scope)) {
                            $to_process_scope = explode(' ', $scope);
                        }

                        $user_scopes = $owner->getScopes();

                        $real_scope = implode(' ', $this->api['security.oauth.get_scopes']($to_process_scope, $user_scopes));

                        if (empty($real_scope) xor empty($user_scopes)) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_scope';
                            $error_description = 'The requested scope is invalid, unknown or malformed.';

                            break;
                        }
                    }

                    break;

                default:
                    throw new BlimpHttpException(Response::HTTP_METHOD_NOT_ALLOWED, 'Method not allowed');
            }
        } catch (Exception $e) {
            // TODO 500
            $error_code = Response::HTTP_BAD_REQUEST;
            $error = 'server_error';
            $error_description = 'Unknown error. ' . $e->getMessage();
        }

        $response = new JsonResponse();
        $response->setStatusCode($error_code);

        $data = [];

        if (!empty($error)) {
            $data['error'] = $error;

            if (strlen($error_description) > 0) {
                $data['error_description'] = $error_description;
            }
        } else {
            $code = $api['security.oauth.authorization_code_create']($profile, $client, $real_redirect_uri, $real_scope);

            $dm = $this->api['dataaccess.mongoodm.documentmanager']();

            $dm->persist($code);

            if(!empty($owner)) {
                $action = ' authorization code issued for client \'' . $real_client_id . '\'; ';
                $action .= '\'' . $real_scope . '\' scope allowed; ';

                $activity = new ResourceOwnerActivity();
                $activity->setAction($action);
                $dm->persist($activity);

                $owner->addActivity($activity);

                $dm->persist($owner);
            }

            $dm->flush();

            $data['code'] = $code->getId();
        }

        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        $response->setPrivate();
        $response->setData($data);

        return $response;
    }
}

/*
invalid_request
The request is missing a required parameter, includes an
unsupported parameter value, repeats a parameter,
includes multiple credentials, utilizes more than one
mechanism for authenticating the client, or is otherwise
malformed.

invalid_client
Client authentication failed (e.g. unknown client, no
client authentication included, or unsupported
authentication method).  The authorization server MAY
return an HTTP 401 (Unauthorized) status code to indicate
which HTTP authentication schemes are supported.  If the
client attempted to authenticate via the 'Authorization'
request header field, the authorization server MUST
respond with an HTTP 401 (Unauthorized) status code, and
include the 'WWW-Authenticate' response header field
matching the authentication scheme used by the client.

invalid_grant
The provided authorization grant (e.g. authorization
code, resource owner credentials) is invalid, expired,
revoked, does not match the redirection URI used in the
authorization request, or was issued to another client.

unauthorized_client
The authenticated client is not authorized to use this
authorization grant type.

unsupported_grant_type
The authorization grant type is not supported by the
authorization server.

invalid_scope
The requested scope is invalid, unknown, malformed, or
exceeds the scope granted by the resource owner.
 */
