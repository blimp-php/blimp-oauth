<?php
namespace Blimp\Security\Documents;

use Blimp\DataAccess\Documents\BlimpDocument;
use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;

/** @ODM\Document */
class ResourceOwnerCredentials extends BlimpDocument {
    /**
     * @ODM\ReferenceOne(targetDocument="\Blimp\Security\Documents\ResourceOwner")
     */
    private $owner;

    /** @ODM\String @ODM\Index(unique=true) */
    private $username;

    /** @ODM\String */
    private $password;

    /** @ODM\String */
    private $otpSecret;

    public function setOwner($owner) {
        $this->owner = $owner;
    }
    public function getOwner() {
        return $this->owner;
    }

    public function setUsername($username) {
        $this->username = $username;
    }
    public function getUsername() {
        return $this->username;
    }

    public function setPassword($password) {
        $this->password = $password;
    }
    public function getPassword() {
        return $this->password;
    }

    public function setOtpSecret($otp_secret) {
        $this->otp_secret = $otp_secret;
    }
    public function getOtpSecret() {
        return $this->otp_secret;
    }
}
