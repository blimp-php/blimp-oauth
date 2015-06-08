<?php
namespace Blimp\Security\GrantTypes;

use Blimp\Http\BlimpHttpException;
use Pimple\Container;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class AuthorizationCode {
    public function process(Container $api, $data, $redirect_uri = null) {
        if (array_key_exists('code', $data)) {
            $code = $data['code'];
        }

        if (empty($code)) {
            $this->error_code = Response::HTTP_BAD_REQUEST;
            $this->error = 'invalid_request';
            $this->error_description = 'Missing code parameter.';
            return false;
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
                $this->error_code = Response::HTTP_BAD_REQUEST;
                $this->error = 'invalid_grant';
                $this->error_description = 'Authorization code was issued to another client.';
                return false;
            }

            if ($item->getExpires() != null && $item->getExpires()->getTimestamp() - time() < 0) {
                $this->error_code = Response::HTTP_BAD_REQUEST;
                $this->error = 'invalid_grant';
                $this->error_description = 'Authorization code has expired.';
                return false;
            }

            if ($item->getUsed()) {
                $this->error_code = Response::HTTP_BAD_REQUEST;
                $this->error = 'invalid_grant';
                $this->error_description = 'Authorization code has already been used.';
                return false;
            }

            if ($item->getRedirectUri() !== $redirect_uri) {
                $this->error_code = Response::HTTP_BAD_REQUEST;
                $this->error = 'invalid_grant';
                $this->error_description = 'redirect_uri does not match the redirection URI used in the authorization request.';
                return false;
            }

            $this->real_scope = $item->getScope();

            $this->profile = $item->getProfile();

            $item->setUsed(true);
            $dm->persist($item);
            $dm->flush();
        } else {
            $this->error_code = Response::HTTP_BAD_REQUEST;
            $this->error = 'invalid_grant';
            $this->error_description = 'Invalid authorization code.';
            return false;
        }
        
        return true;
    }
    
    public function canBePublic() {
        return true;
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
