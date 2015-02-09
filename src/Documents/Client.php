<?php
namespace Blimp\Security\Documents;

use Blimp\DataAccess\Documents\BlimpDocument;
use Blimp\Security\Documents\ClientRedirectURI as ClientRedirectURI;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;

/** @ODM\Document */
class Client extends BlimpDocument {
    /** @ODM\String */
    private $secret;

    /** @ODM\EmbedMany(targetDocument="\Blimp\Security\Documents\ClientRedirectURI") */
    protected $redirectUri;

    public function __construct() {
        $this->redirectUri = new ArrayCollection();
    }

    public function setSecret($secret) {
        $this->secret = $secret;
    }
    public function getSecret() {
        return $this->secret;
    }

    public function setRedirectUri($redirectUri) {
        $this->redirectUri = $redirectUri;
    }
    public function getRedirectUri() {
        return $this->redirectUri;
    }

    public function addRedirectUri(ClientRedirectURI $redirect_uri) {
        $this->redirectUri->add($redirect_uri);
    }

    public function removeRedirectUri(ClientRedirectURI $redirect_uri) {
        $this->redirectUri->removeElement($redirect_uri);
    }
}
