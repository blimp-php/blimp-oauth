<?php
namespace Blimp\Security\Authorization;

use Blimp\Security\Authorization\Permission as Permission;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Authorization\Voter\VoterInterface;

class BlimpVoter implements VoterInterface {
    protected $api;

    public function __construct($api) {
        $this->api = $api;
    }

    public function supportsAttribute($attribute) {
        return true;
    }

    public function supportsClass($class) {
        return true;
    }

    public function vote(TokenInterface $token, $object, array $attributes) {
        if(!($token instanceof BlimpToken)) {
            return VoterInterface::ACCESS_DENIED;
        }

        $scopes = $token->getScopes();
        $permissions = $token->getPermissions();

        $all = $this->api['security.roles'];

        foreach ($attributes as $attribute) {
            if(array_key_exists($attribute, $scopes)) {
                return VoterInterface::ACCESS_GRANTED;
            } else {
                list($required_domain, $required_permissions) = explode(':', $attribute);

                if(array_key_exists($required_domain, $permissions)) {
                    $scope = $all[$required_domain];
                    $scope_permissions = $scope->getPermissions();

                    if (empty($required_permissions)) {
                        $required_permissions = $scope_permissions;
                    } else {
                        $required_permissions = array_intersect(explode(',', $required_permissions), $scope_permissions);
                    }

                    $user_required_permissions = array_intersect($user_permissions, $required_permissions);

                    if (count($user_required_permissions) > 0) {
                        return VoterInterface::ACCESS_GRANTED;
                    }
                }
            }
        }

        return VoterInterface::ACCESS_DENIED;
    }
}
