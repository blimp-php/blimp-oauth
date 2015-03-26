<?php
namespace Blimp\Security\Documents;

use Blimp\DataAccess\Documents\BlimpDocument;
use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;

/** @ODM\Document */
class Code extends BlimpDocument {
    /** @ODM\Id(strategy="CUSTOM", options={"class"="\Blimp\DataAccess\BlimpIdProvider"}) */
    protected $id;

    /** @ODM\String */
    private $scope;

    /** @ODM\String */
    private $redirectUri;

    /**
     * @ODM\Date
     */
    protected $expires;

    /** @ODM\String */
    private $clientId;

    /** @ODM\String */
    private $profileId;

    /** @ODM\Boolean */
    public $used;

    /**
     * @ODM\ReferenceOne(targetDocument="\Blimp\Security\Documents\Client")
     */
    private $client;

    /**
     * @ODM\ReferenceOne
     */
    private $profile;

    public function setScope($scope) {
        $this->scope = $scope;
    }
    public function getScope() {
        return $this->scope;
    }

    public function setRedirectUri($redirectUri) {
        $this->redirectUri = $redirectUri;
    }
    public function getRedirectUri() {
        return $this->redirectUri;
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

    public function setUsed($used) {
        $this->used = $used;
    }
    public function getUsed() {
        return $this->used;
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
}
