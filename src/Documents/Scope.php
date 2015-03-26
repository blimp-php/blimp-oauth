<?php
namespace Blimp\Security\Documents;

use Blimp\DataAccess\Documents\BlimpDocument;
use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use Symfony\Component\Security\Core\Role\RoleInterface;

/** @ODM\Document */
class Scope extends BlimpDocument implements RoleInterface {
    /** @ODM\Id(strategy="CUSTOM", options={"class"="\Blimp\DataAccess\BlimpIdProvider"}) */
    protected $id;

    /** @ODM\Collection */
    protected $scopes;

    public function __construct() {
        $this->scopes = [];
    }

    public function setScopes($scopes) {
        $this->scopes = $scopes;
    }

    public function getScopes() {
        return $this->scopes != null ? $this->scopes : [];
    }

    public function addScope($scope) {
        $this->scopes[] = $scope;
    }

    public function removeScope($scope) {
        $this->scopes->removeElement($scope);
    }

    public function getRole() {
        return $this->id;
    }
}
