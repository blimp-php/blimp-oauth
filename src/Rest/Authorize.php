<?php
namespace Blimp\Security\Rest;

use Blimp\Http\BlimpHttpException;
use Pimple\Container;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Authorize {
    public function process(Container $api, Request $request, array $parameters) {
        // inputs
        $response_type = $request->query->get('response_type');

        $client_id = $request->query->get('client_id');
        $redirect_uri = $request->query->get('redirect_uri');
        $scope = $request->query->get('scope');
        $state = $request->query->get('state');

        $display = $request->query->get('display');

        $denied = $request->query->get('denied');

        // outputs
        $real_redirect_uri = '';

        $code = '';

        $access_token = '';
        $token_type = '';
        $real_scope = '';

        $expires_in = 3600;

        $error = '';
        $error_description = '';
        $error_uri = '';

        try {
            switch ($request->getMethod()) {
                case 'GET':
                    if ($client_id == null) {
                        $error = 'invalid_request';
                        $error_description = 'Missing client_id parameter.';
                        break;
                    }

                    if ($response_type == null) {
                        $error = 'invalid_request';
                        $error_description = 'Missing response_type parameter.';
                        break;
                    }

                    if ($response_type != 'token' && $response_type != 'code') {
                        $error = 'unsupported_response_type';
                        $error_description = 'The authorization server does not support obtaining an authorization using this method.';
                        break;
                    }

                    if ($display != null && $display != 'page' && $display != 'popup' && $display != 'iframe') {
                        $error = 'invalid_request';
                        $error_description = 'Invalid display parameter.';
                        break;
                    }

                    $client_db = $api->getAuthController()->getClient($client_id);
                    if ($client_db == null) {
                        $error = 'unauthorized_client';

                        if ($response_type == 'token') {
                            $error_description = 'The client is not authorized to request an access token.';
                        } else if ($response_type == 'code') {
                            $error_description = 'The client is not authorized to request an authorization code.';
                        }

                        break;
                    }

                    // TODO Public / Confidential + full/parcial + multiple
                    if ($client_db['client_redirecturl'] == null && !$client_db['client_noredirect']) {
                        $error = 'invalid_request';
                        $error_description = 'Unauthorized redirect_uri.';
                        break;
                    } else if ($redirect_uri != null && strpos($redirect_uri, $client_db['client_redirecturl']) != 0) {
                        $error = 'invalid_request';
                        $error_description = 'Unauthorized redirect_uri.';
                        break;
                    } else if ($redirect_uri != null && strlen($redirect_uri) > 0) {
                        $real_redirect_uri = $redirect_uri;
                    } else {
                        $real_redirect_uri = $client_db['client_redirecturl'];
                    }

                    if ($denied != null) {
                        $error = 'access_denied';
                        $error_description = 'The user denied your request.';
                        break;
                    }

                    if ($token == null || $token->getUserID() == null) {
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

                        $next = urlencode($api['config']['base_url'] . '/oauth/authorize?response_type=');
                        $next .= $response_type . '%26client_id%3D' . urlencode($client_id);
                        if ($redirect_uri != null) {
                            $next . '%26redirect_uri%3D' . urlencode($redirect_uri);
                        }
                        if ($scope != null) {
                            $next . '%26scope%3D' . urlencode($scope);
                        }
                        if ($state != null) {
                            $next . '%26state%3D' . urlencode($state);
                        }
                        if ($display != null) {
                            $next . '%26display%3D' . urlencode($display);
                        }

                        $destination_uri = $this->api['config']['frontend_base_url'] . '/login.php?client_id=' . $client_id . '&display=' . ($display != null ? $display : 'page');
                        $destination_uri .= '&cancel_url=' . urlencode($cancel);
                        $destination_uri . '&next=' . urlencode($next);

                        $response = new RedirectResponse($destination_uri);
                        $response->headers->set('Cache-Control', 'no-store');
                        $response->headers->set('Pragma', 'no-cache');
                        $response->setPrivate();

                        return $response;
                    }

                    if ($scope == null) {
                        $error = 'invalid_scope';
                        $error_description = 'The requested scope is invalid, unknown or malformed.';
                        break;
                    }

                    $real_scope = AuthorizeController::processScopes($this->getAPI(), $scope, $token->getUserID());

                    if (strlen($real_scope) == 0) {
                        $error = 'invalid_scope';
                        $error_description = 'The requested scope is invalid, unknown or malformed.';
                        break;
                    }

                    if ($response_type == 'token') {
                        $client_secret = $client_db['client_secret'];
                        $user_id = $token->getUserID();

                        $token = new KToken($client_id, $client_secret, $real_user_id, $real_scope, time(null) + expires_in);
                        $ktoken->setPrivateKey($this->api['config']['ktoken_encryption_private_key']);

                        $access_token = $token->getAccessToken();
                        $token_type = 'bearer';
                    } else if ($response_type == 'code') {
                        $data = $client_id . ':' . urlencode($real_redirect_uri) . ':';
                        if (strlen($real_scope) > 0) {
                            $data .= urlencode($real_scope);
                        }
                        $data .= ':' . $token->getUserID() . ':';

                        // TODO Codificar info e por base64

                        $code = $data;
                    }

                    break;

                default:
                    throw new BlimpHttpException(Response::HTTP_METHOD_NOT_ALLOWED, "Method not allowed");
            }
        } catch (Exception $e) {
            $error = 'server_error';
            $error_description = 'Unknown error. ' . $e->getMessage();
        }

        if ($real_redirect_uri == null && strlen($real_redirect_uri) == 0 && $redirect_uri != null && strlen($redirect_uri) > 0) {
            $real_redirect_uri = $redirect_uri;
        }

        if ($real_redirect_uri != null && strlen($real_redirect_uri) > 0) {
            $next_separator = '&';

            $destination_uri = $real_redirect_uri;
            if ($response_type != null && $response_type == 'token') {
                if (strpos($real_redirect_uri, '#') == -1) {
                    $next_separator = '#';
                }
            } else {
                if (strpos($real_redirect_uri, '?') === false) {
                    $next_separator = '?';
                }
            }

            if (strlen($error) > 0) {
                $destination_uri .= $next_separator . 'error=' . $error;
                $next_separator = '&';

                if (strlen($error_description) > 0) {
                    $destination_uri .= $next_separator . 'error_description=' . urlencode($error_description);
                }

                if (strlen($error_uri) > 0) {
                    $destination_uri .= $next_separator . 'error_uri=' . urlencode($error_uri);
                }
            } else if (strlen($access_token) > 0) {
                $destination_uri .= $next_separator . 'access_token=' . $access_token;
                $next_separator = '&';

                if (strlen($token_type) > 0) {
                    $destination_uri .= $next_separator . 'token_type=' . $token_type;
                }

                if ($expires_in > 0) {
                    $destination_uri .= $next_separator . 'expires_in=' . $expires_in;
                }

                if (strlen($real_scope) > 0) {
                    $destination_uri .= $next_separator . 'scope=' . $scope;
                }
            } else if (strlen($code) > 0) {
                $destination_uri .= $next_separator . 'code=' . $code;
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
            $response = new Response('Missing, invalid, or mismatching redirection URI.', Response::HTTP_BAD_REQUEST);
            $response->headers->set('Cache-Control', 'no-store');
            $response->headers->set('Pragma', 'no-cache');
            $response->setPrivate();

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
