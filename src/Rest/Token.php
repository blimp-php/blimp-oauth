<?php
namespace Blimp\Security\Rest;

use Blimp\Http\BlimpHttpException;
use Pimple\Container;
use Blimp\Security\Documents\AccessToken;
use Blimp\Security\Documents\ResourceOwnerActivity;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Token {
    protected $api;

    public function process(Container $api, Request $request) {
        $this->api = $api;

        $data = $request->attributes->get('data');

        // inputs
        $grant_type = $data['grant_type'];

        $client_id = $data['client_id'];
        $client_secret = $data['client_secret'];

        /* grant_type=authorization_code */
        $code = $data['code'];
        $redirect_uri = $data['redirect_uri'];

        /* grant_type=password */
        // TODO: Since this access token request utilizes the resource owner's
        // password, the authorization server MUST protect the endpoint against
        // brute force attacks (e.g., using rate-limitation or generating
        // alerts).
        $username = $data['username'];
        $password = $data['password'];
        $scope = $data['scope'];

        /* grant_type=client_credentials */

        /* grant_type=refresh_token */
        // TODO $refresh_token = $data['refresh_token');

        // outputs
        $access_token = '';
        $token_type = '';
        $real_scope;
        $expires_in = 3600;

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

                    if ($grant_type === null) {
                        $error_code = Response::HTTP_BAD_REQUEST;
                        $error = 'invalid_request';
                        $error_description = 'Missing authorization grant type.';
                        break;
                    }

                    // Por agora não suportamos client_credentials e refresh_token
                    if ($grant_type !== null && $grant_type !== 'authorization_code' && $grant_type !== 'password' && $grant_type !== 'client_credentials'/* && $grant_type !== 'refresh_token'*/) {
                        $error_code = Response::HTTP_BAD_REQUEST;
                        $error = 'unsupported_grant_type';
                        $error_description = 'The authorization grant type is not supported by the authorization server.';
                        break;
                    }

                    $authorization_header = null;
                    if ($request->headers->has('authorization')) {
                        $authorization_header = $auth = $request->headers->get('authorization');
                    } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
                        $authorization_header = $_SERVER['HTTP_AUTHORIZATION'];
                    } else if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
                        $authorization_header = $_SERVER['PHP_AUTH_DIGEST'];
                    }

                    if ($authorization_header !== null) {
                        if ($client_id !== null || $client_secret !== null) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_request';
                            $error_description = 'The request utilizes more than one mechanism for authenticating the client.';
                            break;
                        }

                        if (strpos($authorization_header, 'Basic') === 0) {
                            $real_client_id = $request->headers->get('PHP_AUTH_USER');
                            $real_client_secret = $request->headers->get('PHP_AUTH_PW');

                            if ($real_client_id === null || $real_client_secret === null) {
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
                        if ($client_id === null) {
                            $error_code = Response::HTTP_UNAUTHORIZED;
                            $error = 'invalid_client';
                            $error_description = 'No client authentication included.';
                            break;
                        }

                        $real_client_id = $client_id;
                        $real_client_secret = $client_secret !== null ? $client_secret : '';
                    }

                    $client = $this->getClient($real_client_id);
                    if ($client === null) {
                        $error_code = Response::HTTP_UNAUTHORIZED;
                        $error = 'invalid_client';
                        $error_description = 'Invalid client_id.';
                        break;
                    }

                    $must_be_public = false;
                    if (empty($real_client_secret)) {
                        $must_be_public = true;
                    } else {
                        if ($client->getSecret() !== $real_client_secret) {
                            $error_code = Response::HTTP_UNAUTHORIZED;
                            $error = 'invalid_client';
                            $error_description = 'Client authentication failed.';
                            break;
                        }

                        $must_be_public = false;
                    }

                    $real_redirect_uri = '';

                    $uris = $client->getRedirectURI();
                    $found = false;
                    if ($redirect_uri !== null) {
                        foreach ($uris as $uri) {
                            $client_redirecturl = $uri->getUri();
                            if (strpos($redirect_uri, $client_redirecturl) === 0) {
                                $parcial = $uri->getParcial();
                                if ($parcial || $redirect_uri === $client_redirecturl) {
                                    if(!$must_be_public || $uri->getPublic()) {
                                        $found = true;
                                        break;
                                    }
                                }
                            }
                        }
                    }

                    if ($redirect_uri !== null && !$found) {
                        $error_code = Response::HTTP_BAD_REQUEST;
                        $error = 'invalid_request';
                        $error_description = 'Unauthorized redirect_uri.';
                        break;
                    } else if ($must_be_public && !$found) {
                        $error_code = Response::HTTP_UNAUTHORIZED;
                        $error = 'invalid_client';
                        $error_description = 'Invalid client authentication.';
                        break;
                    } else if ($redirect_uri !== null) {
                        $real_redirect_uri = $redirect_uri;
                    } else if (count($uris) > 0) {
                        $uri = $uris[0];
                        $client_redirecturl = $uri->getUri();
                        $real_redirect_uri = $client_redirecturl;
                    }

                    $to_process_scope = [];

                    if ($grant_type === 'authorization_code') {
                        if ($code === null) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_request';
                            $error_description = 'Missing code parameter.';
                            break;
                        }

                        $toUnserialize = $code;

                        $code_client_id = '';
                        $code_redirect_uri = '';
                        $code_scope = '';
                        $code_user_id = '';

                        // TODO Descodificar info e tirar base64

                        // TODO Como saber se code já foi usado, para poder enviar invalid_grant?

                        if ($code_client_id !== $real_client_id) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_grant';
                            $error_description = 'Code was issued to another client.';
                            break;
                        }

                        if ($code_redirect_uri !== $real_redirect_uri) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_grant';
                            $error_description = 'redirect_uri does not match the redirection URI used in the authorization request.';
                            break;
                        }

                        $to_process_scope = explode(' ', $code_scope);
                    } else if ($grant_type === 'password') {
                        if ($username === null) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_request';
                            $error_description = 'Missing username parameter.';
                            break;
                        }

                        if ($password === null) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_request';
                            $error_description = 'Missing password parameter.';
                            break;
                        }

                        $owner = $this->getResourceOwner($username, $password);

                        if ($owner === null) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_grant';
                            $error_description = 'Invalid resource owner credentials.';
                            break;
                        }

                        if ($scope !== null) {
                            $to_process_scope = explode(' ', $scope);
                        }

                        $user_scopes = $owner->getScopes();

                        $real_scope = $this->getScopes($to_process_scope, $user_scopes);

                        if (empty($real_scope) xor empty($user_scopes)) {
                            $error_code = Response::HTTP_BAD_REQUEST;
                            $error = 'invalid_scope';
                            $error_description = 'The requested scope is invalid, unknown or malformed.';

                            break;
                        }
                    }

                    $token_type = 'Bearer';

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
            $t = new AccessToken();

            $data['token_type'] = $token_type;

            if (!empty($real_scope)) {
                $data['scope'] = implode(' ', $real_scope);
                $t->setScope($data['scope']);
            }

            if ($expires_in > 0) {
                $data['expires_in'] = $expires_in;

                $date = new \DateTime();
                $date->add(new \DateInterval('PT' . $expires_in . 'S'));

                $t->setExpires($date);
            }

            $payload = \bin2hex(\openssl_random_pseudo_bytes(32));
            $safe_payload = str_replace(array('+', '/', '='), array('-', '_', ''), base64_encode($payload));

            $access_token = $safe_payload;

            $data['access_token'] = $access_token;

            $t->setId($data['access_token']);
            $t->setType($data['token_type']);

            $t->setClientId($client->getId());
            $t->setClient($client);

            if ($grant_type !== 'client_credentials') {
                $t->setProfileId($owner->getProfile()->getId());
                $t->setProfile($owner->getProfile());
            }

            $dm = $this->api['dataaccess.mongoodm.documentmanager']();

            $dm->persist($t);

            if ($grant_type !== 'client_credentials') {
                $action = $token_type . ' access token issued for client \'' . $real_client_id . '\'; ';
                $action .= $grant_type . ' authorization grant presented; ';
                $action .= '\'' . $real_scope . '\' scope allowed; ';

                $activity = new ResourceOwnerActivity();
                $activity->setAction($action);
                $dm->persist($activity);

                $owner->addActivity($activity);

                $dm->persist($owner);
            }

            $dm->flush();
        }

        $response->headers->set('Cache-Control', 'no-store');
        $response->headers->set('Pragma', 'no-cache');
        $response->setPrivate();
        $response->setData($data);

        return $response;
    }

    public function getClient($client_id) {
        $dm = $this->api['dataaccess.mongoodm.documentmanager']();

        $client = $dm->find('Blimp\Security\Documents\Client', $client_id);

        if ($client !== null) {
            return $client;
        }

        return null;
    }

    public function getScopes($requested_scopes, $user_scopes) {
        $authorized_scopes = [];

        foreach ($requested_scopes as $requested_scope) {
            $authorized_domain = null;
            $authorized_permissions = [];

            list($domain, $permissions) = explode(':', $requested_scope);

            foreach ($user_scopes as $user_scope) {
                list($u_domain, $u_permissions) = explode(':', $user_scope);

                if ($u_domain === $domain) {
                    $authorized_domain = $domain;

                    if (empty($u_permissions)) {
                        if (empty($permissions)) {
                            // permissions not specified (all domain)
                            $authorized_permissions = null;
                        } else {
                            // all requested permissions
                            $authorized_permissions = explode(',', $permissions);
                        }

                        break;
                    }

                    $u_permissions = explode(',', $u_permissions);

                    if (empty($permissions)) {
                        // all permited permissions
                        $authorized_permissions = array_merge($authorized_permissions, $u_permissions);
                    } else {
                        // only requested and permited permissions
                        $authorized_permissions = array_merge($authorized_permissions, array_intersect($u_permissions, explode(',', $permissions)));
                    }
                }

                if ($authorized_permissions !== null && count($authorized_permissions) === 0) {
                    // none of the requested permissions is permited, so domain is restricted
                    $authorized_domain = null;
                }
            }

            if ($authorized_domain !== null) {
                $authorized_scope = $authorized_domain;

                if (!empty($authorized_permissions)) {
                    $authorized_scope .= ':' . implode(',', $authorized_permissions);
                }

                $authorized_scopes[] = $authorized_scope;
            }
        }

        return $authorized_scopes;
    }

    public function getResourceOwner($username, $password) {
        $dm = $this->api['dataaccess.mongoodm.documentmanager']();

        $credentials = $dm->getRepository('Blimp\Security\Documents\ResourceOwnerCredentials')->findOneBy(array('username' => $username));

        if ($credentials !== null) {
            if ($credentials->getPassword() !== null) {
                if (!password_verify($password, $credentials->getPassword())) {
                    return null;
                }
            }

            $owner = $credentials->getOwner();
            return $owner;
        }

        return null;
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
