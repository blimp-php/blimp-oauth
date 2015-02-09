<?php
namespace Blimp\Security\Documents;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;

/** @ODM\EmbeddedDocument */
class ClientRedirectURI {
    /** @ODM\String */
    private $uri;

    /** @ODM\Boolean */
    private $parcial;

    /** @ODM\Boolean */
    private $public;

    public function getUri() {
        return $this->uri;
    }

    public function setUri($uri) {
        $this->uri = $uri;
    }

    public function getParcial() {
        return $this->parcial;
    }

    public function setParcial($parcial) {
        $this->parcial = $parcial;
    }

    public function getPublic() {
        return $this->public;
    }

    public function setPublic($public) {
        $this->public = $public;
    }
}
