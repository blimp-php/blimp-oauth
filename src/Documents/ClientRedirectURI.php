<?php
namespace Blimp\Security\Documents;

use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;

/** @ODM\EmbeddedDocument */
class ClientRedirectURI {
    /** @ODM\String */
    protected $uri;

    /** @ODM\Boolean */
    protected $parcial;

    /** @ODM\Boolean */
    protected $public;

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
