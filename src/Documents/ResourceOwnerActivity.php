<?php
namespace Blimp\Security\Documents;

use Blimp\DataAccess\Documents\BlimpDocument;
use Doctrine\ODM\MongoDB\Mapping\Annotations as ODM;
use Gedmo\Mapping\Annotation as Gedmo;

/** @ODM\Document */
class ResourceOwnerActivity extends BlimpDocument {
    /**
     * @ODM\ReferenceOne(targetDocument="\Blimp\Security\Documents\ResourceOwner", inversedBy="activity")
     */
    protected $owner;

    /** @ODM\String */
    protected $action;

    /**
     * @Gedmo\IpTraceable(on="create")
     * @ODM\String
     */
    protected $from;

    public function setOwner($owner) {
        $this->owner = $owner;
    }

    public function getOwner() {
        return $this->owner;
    }

    public function setAction($action) {
        $this->action = $action;
    }

    public function getAction() {
        return $this->action;
    }

    public function setFrom($from) {
        $this->from = $from;
    }

    public function getFrom() {
        return $this->from;
    }
}
