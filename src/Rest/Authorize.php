<?php
namespace Blimp\Security\Rest;

use Blimp\Http\BlimpHttpException;
use Pimple\Container;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\JsonResponse;
use Blimp\Security\Documents\ResourceOwnerActivity;

class Authorize {
    public function process(Container $api, Request $request) {
        // inputs
        $response_type = $request->query->get('response_type');

        $client_id = $request->query->get('client_id');
        $redirect_uri = $request->query->get('redirect_uri');
        $scope = $request->query->get('scope');
        $state = $request->query->get('state');

        $display = $request->query->get('display');

        $denied = $request->query->get('denied');

        $received_error = $request->query->get('error');
        $received_error_description = $request->query->get('error_description');

        // outputs
        $code = null;
        $access_token = null;

        $real_redirect_uri = '';
        $real_scope = '';

        $error_code = Response::HTTP_OK;
        $error = '';
        $error_description = '';

        if ($client_id == null) {
            $error_code = Response::HTTP_BAD_REQUEST;
            $error = 'invalid_request';
            $error_description = 'Missing client_id parameter.';
        }

        if ($response_type == null) {
            $error_code = Response::HTTP_BAD_REQUEST;
            $error = 'invalid_request';
            $error_description = 'Missing response_type parameter.';
        }

        if ($response_type != 'token' && $response_type != 'code') {
            $error_code = Response::HTTP_BAD_REQUEST;
            $error = 'unsupported_response_type';
            $error_description = 'The authorization server does not support obtaining an authorization using this method.';
        }

        if ($display != null && $display != 'page' && $display != 'popup' && $display != 'iframe') {
            $error_code = Response::HTTP_BAD_REQUEST;
            $error = 'invalid_request';
            $error_description = 'Invalid display parameter.';
        }

        $client = $api['security.oauth.get_client']($client_id);
        if ($client == null) {
            $error_code = Response::HTTP_UNAUTHORIZED;
            $error = 'invalid_client';
            $error_description = 'Invalid client_id.';
        }

        if ($denied != null) {
            $error_code = Response::HTTP_UNAUTHORIZED;
            $error = 'access_denied';
            $error_description = 'The user denied your request.';
        }

        $must_be_public = ($response_type == 'token');

        if(empty($error)) {
            $uris = $client->getRedirectURI();
            $found = false;
            if (!empty($redirect_uri)) {
                foreach ($uris as $uri) {
                    $client_redirecturl = $uri->getUri();
                    if (strpos($redirect_uri, $client_redirecturl) === 0) {
                        $parcial = $uri->getParcial();
                        if ($parcial || $redirect_uri === $client_redirecturl) {
                            if (!$must_be_public || $uri->getPublic()) {
                                $found = true;
                                break;
                            }
                        }
                    }
                }
            }

            if (!empty($redirect_uri) && !$found) {
                $error_code = Response::HTTP_BAD_REQUEST;
                $error = 'invalid_request';
                $error_description = 'Unauthorized redirect_uri.';
            } else if ($must_be_public && !$found) {
                $error_code = Response::HTTP_UNAUTHORIZED;
                $error = 'invalid_client';
                $error_description = 'Invalid client authentication.';
            } else if ($redirect_uri !== null) {
                $real_redirect_uri = $redirect_uri;
            } else if (count($uris) > 0) {
                $uri = $uris[0];
                $client_redirecturl = $uri->getUri();
                $real_redirect_uri = $client_redirecturl;
            }

            if(empty($error)) {
                $cancel = urlencode($real_redirect_uri);
                if ($response_type == 'token') {
                    if (strpos($real_redirect_uri, '#') == -1) {
                        $cancel .= '%23';
                    } else {
                        $cancel .= '%26';
                    }
                } else {
                    if (strpos($real_redirect_uri, '?') == -1) {
                        $cancel .= '%3F';
                    } else {
                        $cancel .= '%26';
                    }
                }

                $cancel .= 'error%3Daccess_denied%26error_description=' . urlencode('The user denied your request.');

                $baseurl = $request->getScheme() . '://' . $request->getHttpHost() . $request->getBasePath() . $request->getPathInfo();
                $next = urlencode($baseurl . '?response_type=');
                $next .= $response_type . '%26client_id%3D' . urlencode($client_id);
                if ($redirect_uri != null) {
                    $next .= '%26redirect_uri%3D' . urlencode($redirect_uri);
                }
                if ($scope != null) {
                    $next .= '%26scope%3D' . urlencode($scope);
                }
                if ($state != null) {
                    $next .= '%26state%3D' . urlencode($state);
                    $cancel .= '%26state%3D' . urlencode($state);
                }
                if ($display != null) {
                    $next .= '%26display%3D' . urlencode($display);
                }

                try {
                    switch ($request->getMethod()) {
                        case 'GET':
                            $destination_uri = $api['security.oauth.login_url'] . '?client_id=' . $client_id . '&display=' . ($display != null ? $display : 'page');
                            $destination_uri .= '&cancel_url=' . urlencode($cancel);
                            $destination_uri .= '&next=' . urlencode($next);

                            if (!empty($received_error)) {
                                $destination_uri .= '&error=' . $received_error;

                                if (!empty($received_error_description)) {
                                    $destination_uri .= '&error_description=' . urlencode($received_error_description);
                                }
                            }

                            $response = new RedirectResponse($destination_uri);
                            $response->headers->set('Cache-Control', 'no-store');
                            $response->headers->set('Pragma', 'no-cache');
                            $response->setPrivate();

                            return $response;

                            break;

                        case 'POST':
                            $data = $request->attributes->get('data');
                            if (array_key_exists('username', $data)) {
                                $username = $data['username'];
                            }
                            if (array_key_exists('password', $data)) {
                                $password = $data['password'];
                            }

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

                            $owner = $api['security.oauth.get_resource_owner']($username, $password);

                            if (empty($owner)) {
                                $error_code = Response::HTTP_BAD_REQUEST;
                                $error = 'invalid_grant';
                                $error_description = 'Invalid resource owner credentials.';

                                $destination_uri = $api['security.oauth.login_url'] . '?client_id=' . $client_id . '&display=' . ($display != null ? $display : 'page');
                                $destination_uri .= '&cancel_url=' . urlencode($cancel);
                                $destination_uri .= '&next=' . urlencode($next);
                                $destination_uri .= '&error=' . $error;
                                $destination_uri .= '&error_description=' . urlencode($error_description);

                                $response = new RedirectResponse($destination_uri);
                                $response->headers->set('Cache-Control', 'no-store');
                                $response->headers->set('Pragma', 'no-cache');
                                $response->setPrivate();

                                return $response;
                            }

                            $profile = $owner->getProfile();

                            if (!empty($scope)) {
                                $to_process_scope = explode(' ', $scope);
                            }

                            $user_scopes = $owner->getScopes();

                            $real_scope = implode(' ', $api['security.oauth.get_scopes']($to_process_scope, $user_scopes));

                            if (empty($real_scope) xor empty($user_scopes)) {
                                $error_code = Response::HTTP_BAD_REQUEST;
                                $error = 'invalid_scope';
                                $error_description = 'The requested scope is invalid, unknown or malformed.';

                                break;
                            }

                            if ($response_type == 'code') {
                                $code = $api['security.oauth.authorization_code_create']($profile, $client, $real_redirect_uri, $real_scope);
                                $dm = $api['dataaccess.mongoodm.documentmanager']();

                                $dm->persist($code);

                                if(!empty($owner)) {
                                    $action = ' authorization code issued for client \'' . $client_id . '\'; ';
                                    $action .= '\'' . $real_scope . '\' scope allowed; ';

                                    $activity = new ResourceOwnerActivity();
                                    $activity->setAction($action);
                                    $dm->persist($activity);

                                    $owner->addActivity($activity);

                                    $dm->persist($owner);
                                }

                                $dm->flush();
                            } else if ($response_type == 'token') {
                                $access_token = $api['security.oauth.access_token_create']($profile, $client, $real_scope);

                                $dm = $api['dataaccess.mongoodm.documentmanager']();

                                $dm->persist($access_token);

                                if (!empty($owner)) {
                                    $action = $access_token->getType() . ' access token issued for client \'' . $access_token->getClientId() . '\'; ';
                                    $action .= '\'' . $access_token->getScope() . '\' scope allowed; ';

                                    $activity = new ResourceOwnerActivity();
                                    $activity->setAction($action);
                                    $dm->persist($activity);

                                    $owner->addActivity($activity);

                                    $dm->persist($owner);
                                }

                                $dm->flush();
                            }

                            break;

                        default:
                            throw new BlimpHttpException(Response::HTTP_METHOD_NOT_ALLOWED, "Method not allowed");
                    }
                } catch (Exception $e) {
                    $error_code = Response::HTTP_INTERNAL_SERVER_ERROR;
                    $error = 'server_error';
                    $error_description = 'Unknown error. ' . $e->getMessage();
                }
            }
        }

        if ($real_redirect_uri == null && strlen($real_redirect_uri) == 0 && $redirect_uri != null && strlen($redirect_uri) > 0) {
            $real_redirect_uri = $redirect_uri;
        }

        if ($real_redirect_uri != null && strlen($real_redirect_uri) > 0) {
            $next_separator = '&';

            $destination_uri = $real_redirect_uri;
            if ($response_type != null && $response_type == 'token') {
                if (strpos($real_redirect_uri, '#') === false) {
                    $next_separator = '#';
                }
            } else {
                if (strpos($real_redirect_uri, '?') === false) {
                    $next_separator = '?';
                }
            }

            if (!empty($error)) {
                $destination_uri .= $next_separator . 'error=' . $error;
                $next_separator = '&';

                if (strlen($error_description) > 0) {
                    $destination_uri .= $next_separator . 'error_description=' . urlencode($error_description);
                }
            } else if (!empty($access_token)) {
                $destination_uri .= $next_separator . 'access_token=' . $access_token->getId();
                $next_separator = '&';

                $destination_uri .= $next_separator . 'token_type=' . $access_token->getType();

                $destination_uri .= $next_separator . 'expires_in=' . $access_token->expiresIn;

                $destination_uri .= $next_separator . 'scope=' . $access_token->getScope();
            } else if (!empty($code)) {
                $destination_uri .= $next_separator . 'code=' . $code->getId();
                $next_separator = '&';
            }

            if (strlen($state) > 0) {
                $destination_uri .= $next_separator . 'state=' . $state;
                $next_separator = '&';
            }

            $response = new RedirectResponse($destination_uri);
            $response->headers->set('Cache-Control', 'no-store');
            $response->headers->set('Pragma', 'no-cache');
            $response->setPrivate();

            return $response;
        } else {
            $data = [];

            if (!empty($error)) {
                $data['error'] = $error;

                if (strlen($error_description) > 0) {
                    $data['error_description'] = $error_description;
                }
            } else {
                $error_code = Response::HTTP_BAD_REQUEST;
                $data['error'] = 'invalid_request';
                $data['error_description'] = 'Missing, invalid, or mismatching redirection URI.';
            }

            $response = new JsonResponse();
            $response->setStatusCode($error_code);
            $response->headers->set('Cache-Control', 'no-store');
            $response->headers->set('Pragma', 'no-cache');
            $response->setPrivate();
            $response->setData($data);

            return $response;
        }
    }
}

/*
invalid_request
The request is missing a required parameter, includes an
invalid parameter value, or is otherwise malformed.

unauthorized_client
The client is not authorized to request an authorization
code using this method.

access_denied
The resource owner or authorization server denied the
request.

unsupported_response_type
The authorization server does not support obtaining an
authorization code using this method.

invalid_scope
The requested scope is invalid, unknown, or malformed.

server_error
The authorization server encountered an unexpected
condition which prevented it from fulfilling the request.

temporarily_unavailable
The authorization server is currently unable to handle
the request due to a temporary overloading or maintenance
of the server.
 */
