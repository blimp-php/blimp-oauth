<?php
namespace Blimp\Security\Documents;

use Blimp\DataAccess\Documents\BlimpDocument;
use Blimp\Security\Documents\ResourceOwnerActivity as ResourceOwnerActivity;
use Blimp\Security\Documents\ResourceOwnerCredentials as ResourceOwnerCredentials;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;

/** @ODM\Document */
class ResourceOwner extends BlimpDocument {
    /**
     * @ODM\ReferenceOne
     */
    private $profile;

    /** @ODM\ReferenceMany(targetDocument="\Blimp\Security\Documents\ResourceOwnerActivity", mappedBy="owner", cascade={"persist"}, orphanRemoval=true) */
    protected $activity;

    /** @ODM\ReferenceMany(targetDocument="\Blimp\Security\Documents\ResourceOwnerCredentials", mappedBy="owner", cascade={"persist"}, orphanRemoval=true) */
    protected $credentials;

    /** @ODM\Collection */
    protected $scopes;

    public function __construct() {
        $this->activity = new ArrayCollection();
        $this->credentials = new ArrayCollection();
        $this->scopes = [];
    }

    public function setProfile($profile) {
        $this->profile = $profile;
    }

    public function getProfile() {
        return $this->profile;
    }

    public function setActivity($activity) {
        $this->activity = $activity;
    }

    public function getActivity() {
        return $this->activity;
    }

    public function addActivity(ResourceOwnerActivity $activity) {
        $this->activity->add($activity);
        $activity->setOwner($this);
    }

    public function removeActivity(ResourceOwnerActivity $activity) {
        $this->activity->removeElement($activity);
        $activity->setOwner(null);
    }

    public function setCredentials($credentials) {
        $this->credentials = $credentials;
    }

    public function getCredentials() {
        return $this->credentials;
    }

    public function addCredentials(ResourceOwnerCredentials $credentials) {
        $this->credentials->add($credentials);
        $credentials->setOwner($this);
    }

    public function removeCredentials(ResourceOwnerCredentials $credentials) {
        $this->credentials->removeElement($credentials);
        $credentials->setOwner(null);
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
}
