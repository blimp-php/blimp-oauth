<?php
namespace Blimp\Security\Authentication;

use Blimp\Security\Authorization\Permission as Permission;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Role\Role;

class BlimpToken implements TokenInterface {
    protected $bearerToken;

    private $roles = array();
    private $authenticated = false;
    private $attributes = array();

    private $all_scopes = array();
    private $all_permissions = array();

    private $access_token;

    /**
     * Constructor.
     *
     * @param RoleInterface[] $roles An array of roles
     *
     * @throws \InvalidArgumentException
     */
    public function __construct(array $roles = array(), array $all = []) {
        $admin = false;

        foreach ($roles as $role) {
            if (is_string($role)) {
                $role = new Role($role);
            } elseif (!$role instanceof RoleInterface) {
                throw new \InvalidArgumentException(sprintf('$roles must be an array of strings, or RoleInterface instances, but got %s.', gettype($role)));
            }

            $this->roles[] = $role;
        }

        $admin = $this->processScopes($all, $this->roles, true);
        if ($admin) {
            foreach ($all as $domain => $scope) {
                if ($scope instanceof Permission) {
                    $this->addPermission($domain, $scope->getPermissions());
                } else {
                    $this->addScope($domain, $scope);
                }
            }
        }
    }

    private function processScopes(array $all, array $roles, $top = false) {
        foreach ($roles as $role) {
            $role_name = $top ? $role->getRole() : $role;

            if ($role_name == '*') {
                return true;
            }

            list($user_domain, $user_permissions) = explode(':', $role_name);

            if (array_key_exists($user_domain, $all)) {
                $scope = $all[$user_domain];

                if ($scope instanceof Permission) {
                    $scope_permissions = $scope->getPermissions();

                    if (empty($user_permissions) || $user_permissions == '*') {
                        $user_permissions = $scope_permissions;
                    } else {
                        $user_permissions = array_intersect(explode(',', $user_permissions), $scope_permissions);
                    }

                    $this->addPermission($user_domain, $user_permissions);
                } else {
                    $this->addScope($user_domain, $scope);

                    if($this->processScopes($all, $scope->getScopes())) {
                        return true;
                    }
                }
            }
        }

        return false;
    }

    private function addPermission($domain, $permissions) {
        if (array_key_exists($domain, $this->all_permissions)) {
            $p = $this->all_permissions[$domain];
            $p->setPermissions(array_unique(array_merge($permissions, $p->getPermissions())));
        } else {
            $p = new Permission($domain, $permissions);
            $this->all_permissions[$domain] = $p;
        }
    }

    private function addScope($name, $scope) {
        $this->all_scopes[$name] = $scope;
    }

    public function getScopes() {
        return $this->all_scopes;
    }

    public function getPermissions() {
        return $this->all_permissions;
    }

    public function setCredentials($bearerToken) {
        $this->bearerToken = $bearerToken;
    }

    public function getCredentials() {
        return $this->bearerToken;
    }

    /**
     * {@inheritdoc}
     */
    public function getRoles() {
        return $this->roles;
    }

    /**
     * {@inheritdoc}
     */
    public function getUsername() {
        return $this->access_token != null ? $this->access_token->getProfile()->getId() : '';
    }

    /**
     * {@inheritdoc}
     */
    public function getUser() {
        return $this->access_token->getProfile();
    }

    public function setUser($user) {
    }

    public function setAccessToken($access_token) {
        $this->access_token = $access_token;
    }

    public function getAccessToken() {
        return $this->access_token;
    }

    /**
     * {@inheritdoc}
     */
    public function isAuthenticated() {
        return $this->authenticated;
    }

    /**
     * {@inheritdoc}
     */
    public function setAuthenticated($authenticated) {
        $this->authenticated = (bool) $authenticated;
    }

    /**
     * {@inheritdoc}
     */
    public function eraseCredentials() {
        $this->bearerToken = null;
    }

    /**
     * {@inheritdoc}
     */
    public function serialize() {
        return serialize(
            array(
                $this->profile,
                $this->authenticated,
                $this->roles,
                $this->attributes,
                $this->providerKey
            )
        );
    }

    /**
     * {@inheritdoc}
     */
    public function unserialize($serialized) {
        list($this->user, $this->authenticated, $this->roles, $this->attributes, $this->providerKey) = unserialize($serialized);
    }

    /**
     * Returns the token attributes.
     *
     * @return array The token attributes
     */
    public function getAttributes() {
        return $this->attributes;
    }

    /**
     * Sets the token attributes.
     *
     * @param array $attributes The token attributes
     */
    public function setAttributes(array $attributes) {
        $this->attributes = $attributes;
    }

    /**
     * Returns true if the attribute exists.
     *
     * @param string $name The attribute name
     *
     * @return bool    true if the attribute exists, false otherwise
     */
    public function hasAttribute($name) {
        return array_key_exists($name, $this->attributes);
    }

    /**
     * Returns an attribute value.
     *
     * @param string $name The attribute name
     *
     * @return mixed The attribute value
     *
     * @throws \InvalidArgumentException When attribute doesn't exist for this token
     */
    public function getAttribute($name) {
        if (!array_key_exists($name, $this->attributes)) {
            throw new \InvalidArgumentException(sprintf('This token has no "%s" attribute.', $name));
        }

        return $this->attributes[$name];
    }

    /**
     * Sets an attribute.
     *
     * @param string $name  The attribute name
     * @param mixed  $value The attribute value
     */
    public function setAttribute($name, $value) {
        $this->attributes[$name] = $value;
    }

    /**
     * {@inheritdoc}
     */
    public function __toString() {
        $class = get_class($this);
        $class = substr($class, strrpos($class, '\\') + 1);

        $roles = array();
        foreach ($this->roles as $role) {
            $roles[] = $role->getRole();
        }

        return sprintf('%s(user="%s", authenticated=%s, roles="%s")', $class, $this->getUsername(), json_encode($this->authenticated), implode(', ', $roles));
    }
}
