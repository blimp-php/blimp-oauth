<?php
namespace Blimp\Security\GrantTypes;

use Blimp\Http\BlimpHttpException;
use Pimple\Container;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Password {
    // TODO: Since this access token request utilizes the resource owner's
    // password, the authorization server MUST protect the endpoint against
    // brute force attacks (e.g., using rate-limitation or generating
    // alerts).
    public function process(Container $api, $data, $redirect_uri = null) {
        if (array_key_exists('username', $data)) {
            $username = $data['username'];
        }
        if (array_key_exists('password', $data)) {
            $password = $data['password'];
        }
        if (array_key_exists('scope', $data)) {
            $scope = $data['scope'];
        }

        if (empty($username)) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_request';
          $this->error_description = 'Missing username parameter.';
          return false;
        }

        if (empty($password)) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_request';
          $this->error_description = 'Missing password parameter.';
          return false;
        }

        $owner = $api['security.oauth.get_resource_owner']($username, $password);

        if ($owner === null) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_grant';
          $this->error_description = 'Invalid resource owner credentials.';
          return false;
        }

        $this->profile = $owner->getProfile();

        if (!empty($scope)) {
          $to_process_scope = explode(' ', $scope);
        } else {
          $to_process_scope = [];
        }

        $user_scopes = $owner->getScopes();

        $this->real_scope = implode(' ', $api['security.oauth.get_scopes']($to_process_scope, $user_scopes));

        if (empty($this->real_scope) xor empty($user_scopes)) {
          $this->error_code = Response::HTTP_BAD_REQUEST;
          $this->error = 'invalid_scope';
          $this->error_description = 'The requested scope is invalid, unknown or malformed.';

          return false;
        }
        
        return true;
    }
    
    public function canBePublic() {
        return false;
    }

    public function getProfile() {
        return $this->profile;
    }
    
    public function getScope() {
        return $this->real_scope;
    }
    
    public function getError() {
        if(empty($this->error_code)) {
            return null;
        }
        
        $error = new \stdClass();
        $error->error_code = $this->error_code;
        $error->error = $this->error;
        $error->error_description = $this->error_description;

        return $error;
    }
}
