<?php
namespace Blimp\Security\Authorization;

use Symfony\Component\Security\Core\Role\RoleInterface;

class Permission implements RoleInterface {
    private $domain;
    private $permissions;

    public function __construct($domain, $permissions = []) {
        $this->domain = $domain;
        $this->permissions = $permissions;
    }

    public function getRole() {
        $perms = '';
        if (!empty($this->permissions)) {
            $perms = ':' . implode(',', $this->permissions);
        }

        return $this->domain . $perms;
    }

    public function setDomain($domain) {
        $this->domain = $domain;
    }

    public function getDomain() {
        return $this->domain;
    }

    public function setPermissions($permissions) {
        $this->permissions = $permissions;
    }

    public function getPermissions() {
        return $this->permissions;
    }
}
