<?php
namespace Blimp\Security\Rest;

use Blimp\Http\BlimpHttpException;
use Blimp\Security\Documents\ResourceOwnerActivity;
use Pimple\Container;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Token {
    public function process(Container $api, Request $request) {
        $data = $request->attributes->get('data');

        if (empty($data)) {
            $error_code = Response::HTTP_BAD_REQUEST;
            $error = 'invalid_request';
            $error_description = 'Missing authorization grant type.';
        } else {
          // inputs
          if (array_key_exists('grant_type', $data)) {
              $grant_type = $data['grant_type'];
          }

          if (array_key_exists('client_id', $data)) {
              $client_id = $data['client_id'];
          }
          if (array_key_exists('client_secret', $data)) {
              $client_secret = $data['client_secret'];
          }

          /* grant_type=authorization_code */
          if (array_key_exists('code', $data)) {
              $code = $data['code'];
          }
          if (array_key_exists('redirect_uri', $data)) {
              $redirect_uri = $data['redirect_uri'];
          }

          /* grant_type=password */
          // TODO: Since this access token request utilizes the resource owner's
          // password, the authorization server MUST protect the endpoint against
          // brute force attacks (e.g., using rate-limitation or generating
          // alerts).
          if (array_key_exists('username', $data)) {
              $username = $data['username'];
          }
          if (array_key_exists('password', $data)) {
              $password = $data['password'];
          }
          if (array_key_exists('scope', $data)) {
              $scope = $data['scope'];
          }

          /* grant_type=client_credentials */

          /* grant_type=refresh_token */
          // TODO $refresh_token = $data['refresh_token');

          // outputs
          $access_token = null;

          $real_redirect_uri = '';
          $real_scope = '';

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

                      if (empty($grant_type)) {
                          $error_code = Response::HTTP_BAD_REQUEST;
                          $error = 'invalid_request';
                          $error_description = 'Missing authorization grant type.';
                          break;
                      }

                      // Por agora não suportamos client_credentials e refresh_token
                      if ($grant_type !== 'authorization_code' && $grant_type !== 'password' && $grant_type !== 'client_credentials'/* && $grant_type !== 'refresh_token'*/) {
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
                          if (!empty($client_id) || !empty($client_secret)) {
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
                          if (empty($client_id)) {
                              $error_code = Response::HTTP_UNAUTHORIZED;
                              $error = 'invalid_client';
                              $error_description = 'No client authentication included.';
                              break;
                          }

                          $real_client_id = $client_id;
                          $real_client_secret = !empty($client_secret) ? $client_secret : '';
                      }

                      $client = $api['security.oauth.get_client']($real_client_id);
                      if ($client === null) {
                          $error_code = Response::HTTP_UNAUTHORIZED;
                          $error = 'invalid_client';
                          $error_description = 'Invalid client_id.';
                          break;
                      }

                      $must_be_public = false;
                      if($grant_type !== 'password') {
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
                      }

                      $has_redir_url = !empty($redirect_uri);

                      $uris = $client->getRedirectURI();
                      $found = false;
                      if ($has_redir_url) {
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

                      if ($has_redir_url && !$found) {
                          $error_code = Response::HTTP_BAD_REQUEST;
                          $error = 'invalid_request';
                          $error_description = 'Unauthorized redirect_uri.';
                          break;
                      } else if ($must_be_public && !$found) {
                          $error_code = Response::HTTP_UNAUTHORIZED;
                          $error = 'invalid_client';
                          $error_description = 'Invalid client authentication.';
                          break;
                      } else if ($has_redir_url) {
                          $real_redirect_uri = $redirect_uri;
                      } else if (count($uris) > 0) {
                          $uri = $uris[0];
                          $client_redirecturl = $uri->getUri();
                          $real_redirect_uri = $client_redirecturl;
                      }

                      $to_process_scope = [];

                      if ($grant_type === 'authorization_code') {
                          if (empty($code)) {
                              $error_code = Response::HTTP_BAD_REQUEST;
                              $error = 'invalid_request';
                              $error_description = 'Missing code parameter.';
                              break;
                          }

                          $dm = $api['dataaccess.mongoodm.documentmanager']();

                          $query_builder = $dm->createQueryBuilder();
                          $query_builder->eagerCursor(true);
                          $query_builder->find('Blimp\Security\Documents\Code');

                          $query_builder->field('_id')->equals($code);

                          $query = $query_builder->getQuery();

                          $item = $query->getSingleResult();

                          if ($item != null) {
                              if ($item->getClientId() != $real_client_id) {
                                  $error_code = Response::HTTP_BAD_REQUEST;
                                  $error = 'invalid_grant';
                                  $error_description = 'Authorization code was issued to another client.';
                                  break;
                              }

                              if ($item->getExpires() != null && $item->getExpires()->getTimestamp() - time() < 0) {
                                  $error_code = Response::HTTP_BAD_REQUEST;
                                  $error = 'invalid_grant';
                                  $error_description = 'Authorization code has expired.';
                                  break;
                              }

                              if ($item->getUsed()) {
                                  $error_code = Response::HTTP_BAD_REQUEST;
                                  $error = 'invalid_grant';
                                  $error_description = 'Authorization code has already been used.';
                                  break;
                              }

                              if ($item->getRedirectUri() !== $real_redirect_uri) {
                                  $error_code = Response::HTTP_BAD_REQUEST;
                                  $error = 'invalid_grant';
                                  $error_description = 'redirect_uri does not match the redirection URI used in the authorization request.';
                                  break;
                              }

                              $real_scope = $item->getScope();

                              $profile = $item->getProfile();

                              $item->setUsed(true);
                              $dm->persist($item);
                              $dm->flush();
                          } else {
                              $error_code = Response::HTTP_BAD_REQUEST;
                              $error = 'invalid_grant';
                              $error_description = 'Invalid authorization code.';
                              break;
                          }
                      } else if ($grant_type === 'password') {
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

                          if ($owner === null) {
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

                          $real_scope = implode(' ', $api['security.oauth.get_scopes']($to_process_scope, $user_scopes));

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
            $access_token = $api['security.oauth.access_token_create']($profile, $client, $real_scope);

            $dm = $api['dataaccess.mongoodm.documentmanager']();

            $dm->persist($access_token);

            if (!empty($owner)) {
                $action = $access_token->getType() . ' access token issued for client \'' . $access_token->getClientId() . '\'; ';
                $action .= $grant_type . ' authorization grant presented; ';
                $action .= '\'' . $access_token->getScope() . '\' scope allowed; ';

                $activity = new ResourceOwnerActivity();
                $activity->setAction($action);
                $dm->persist($activity);

                $owner->addActivity($activity);

                $dm->persist($owner);
            }

            $dm->flush();

            $data['access_token'] = $access_token->getId();
            $data['token_type'] = $access_token->getType();
            $data['expires_in'] = $access_token->expiresIn;
            $data['scope'] = $access_token->getScope();
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
