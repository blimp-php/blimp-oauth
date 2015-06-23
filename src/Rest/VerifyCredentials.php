<?php
namespace Blimp\Security\Rest;

use Blimp\Http\BlimpHttpException;
use Blimp\Security\Authentication\BlimpToken;
use Pimple\Container;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class VerifyCredentials {
    public function process(Container $api, Request $request) {
        $data = $request->attributes->get('data');

        // inputs
        if (array_key_exists('input_token', $data)) {
            $input_token = $data['input_token'];
        }

        if (array_key_exists('include_entities', $data)) {
            $include_entities = $data['include_entities'];
        }

        if (array_key_exists('client_id', $data)) {
            $client_id = $data['client_id'];
        }
        if (array_key_exists('client_secret', $data)) {
            $client_secret = $data['client_secret'];
        }

        if (array_key_exists('redirect_uri', $data)) {
            $redirect_uri = $data['redirect_uri'];
        }

        $token = $api['security']->getToken();

        switch ($request->getMethod()) {
            case 'GET':
                if (empty($input_token)) {
                    throw new BlimpHttpException(Response::HTTP_BAD_REQUEST, 'invalid_token', 'The access token to inspect is invalid.');
                }

                $query_builder = $api['dataaccess.mongoodm.documentmanager']()->createQueryBuilder();
                $query_builder->eagerCursor(true);
                $query_builder->find('Blimp\Security\Documents\AccessToken');

                $query_builder->field('_id')->equals($input_token);

                $query = $query_builder->getQuery();

                $access_token = $query->getSingleResult();

                if ($access_token != null) {
                    if ($access_token->getExpires() != null && $access_token->getExpires()->getTimestamp() - time() < 0) {
                        throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_token', 'The access token is expired.');
                    }

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

                    if ($token != null && $token instanceof BlimpToken && $token->isAuthenticated() && $token->getUser() == null) {
                        if (!empty($client_id) || !empty($client_secret)) {
                            throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_client', 'The request utilizes more than one mechanism for authenticating the client.');
                        }

                        $real_client_id = $token->getAccessToken()->getClientID();
                        $real_client_secret = $token->getAccessToken()->getClient()->getSecret();
                    } else if ($authorization_header !== null) {
                        if (!empty($client_id) || !empty($client_secret)) {
                            throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_client', 'The request utilizes more than one mechanism for authenticating the client.');
                        }

                        if (strpos($authorization_header, 'Basic') === 0) {
                            $real_client_id = $request->headers->get('PHP_AUTH_USER');
                            $real_client_secret = $request->headers->get('PHP_AUTH_PW');

                            if ($real_client_id === null || $real_client_secret === null) {
                                throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_client', 'Invalid client authentication.');
                            }
                        } else {
                            throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_client', 'Unsupported client authentication.');
                        }
                    } else {
                        if (empty($client_id)) {
                            throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_client', 'No client authentication included.');
                        }

                        $real_client_id = $client_id;
                        $real_client_secret = !empty($client_secret) ? $client_secret : '';
                    }

                    if($access_token->getClientID() !== $real_client_id) {
                        throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_client', 'Invalid client_id.');
                    }

                    $client = $access_token->getClient();

                    $must_be_public = false;
                    if (empty($real_client_secret)) {
                        $must_be_public = true;
                    } else {
                        if ($client->getSecret() !== $real_client_secret) {
                            throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_client', 'Client authentication failed.');
                        }

                        $must_be_public = false;
                    }

                    $uris = $client->getRedirectURI();
                    $found = false;
                    if (!empty($redirect_uri)) {
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

                    if (!empty($redirect_uri) && !$found) {
                        throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_request', 'Unauthorized redirect_uri.');
                    } else if ($must_be_public && !$found) {
                        throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_client', 'Client authentication failed.');
                    }

                    $data = [];

                    $scope = $access_token->getScope();
                    if(!empty($scope)) {
                        $data['scope'] = $scope;
                    }
                    
                    $df = !empty($api['dataaccess.mongoodm.date_format']);

                    $expires = $access_token->getExpires();
                    if(!empty($expires)) {
                        $data['expires_at'] = $expires;

                        if($df) {
                            $data['expires_at'] = $data['expires_at']->format($api['dataaccess.mongoodm.date_format']);
                        }
                    }

                    $data['issued_at'] = $access_token->getCreated();

                    if($df) {
                        $data['issued_at'] = $data['issued_at']->format($api['dataaccess.mongoodm.date_format']);
                    }
                    
                    $data['client_id'] = $access_token->getClientId();

                    $profile_id = $access_token->getProfileId();
                    if(!empty($profile_id)) {
                        $data['profile_id'] = $profile_id;
                    }

                    if (!empty($include_entities) && boolval($include_entities) && $include_entities != 'false') {
                        $profile = $access_token->getProfile();
                        if(!empty($profile)) {
                            $data['profile'] = $api['dataaccess.mongoodm.utils']->toStdClass($profile, 0, true, true);
                        }
                    }

                    $response = new JsonResponse();
                    $response->setStatusCode(Response::HTTP_OK);
                    $response->headers->set('Cache-Control', 'no-store');
                    $response->headers->set('Pragma', 'no-cache');
                    $response->setPrivate();
                    $response->setData($data);

                    return $response;
                }

                throw new BlimpHttpException(Response::HTTP_UNAUTHORIZED, 'invalid_token', 'The access token is invalid');

                break;

            default:
                throw new BlimpHttpException(Response::HTTP_METHOD_NOT_ALLOWED, 'Method not allowed');
        }
    }
}
