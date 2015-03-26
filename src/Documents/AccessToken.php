<?php
namespace Blimp\Security\Documents;

use Blimp\DataAccess\Documents\BlimpDocument;
use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;

/** @ODM\Document */
class AccessToken extends BlimpDocument {
    /** @ODM\Id(strategy="CUSTOM", options={"class"="\Blimp\DataAccess\BlimpIdProvider"}) */
    protected $id;

    /** @ODM\String */
    private $type;

    /** @ODM\String */
    private $scope;

    /**
     * @ODM\Date
     */
    protected $expires;

    /** @ODM\String */
    private $clientId;

    /** @ODM\String */
    private $profileId;

    /**
     * @ODM\ReferenceOne(targetDocument="\Blimp\Security\Documents\Client")
     */
    private $client;

    /**
     * @ODM\ReferenceOne
     */
    private $profile;

    public function setType($type) {
        $this->type = $type;
    }
    public function getType() {
        return $this->type;
    }

    public function setScope($scope) {
        $this->scope = $scope;
    }
    public function getScope() {
        return $this->scope;
    }

    public function setExpires($expires) {
        $this->expires = $expires;
    }
    public function getExpires() {
        return $this->expires;
    }

    public function setClientId($client_id) {
        $this->clientId = $client_id;
    }
    public function getClientId() {
        return $this->clientId;
    }

    public function setProfileId($profile_id) {
        $this->profileId = $profile_id;
    }
    public function getProfileId() {
        return $this->profileId;
    }

    public function setClient(Client $client) {
        $this->client = $client;
    }
    public function getClient() {
        return $this->client;
    }

    public function setProfile($profile) {
        $this->profile = $profile;
    }
    public function getProfile() {
        return $this->profile;
    }

    // transient
    public $expiresIn;
}
