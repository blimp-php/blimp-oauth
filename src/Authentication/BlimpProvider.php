<?php
namespace Blimp\Security\Authentication;

use Pimple\Container;
use Blimp\Security\Authentication\BlimpToken;
use Symfony\Component\Security\Core\Authentication\Provider\AuthenticationProviderInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationCredentialsNotFoundException;
use Symfony\Component\Security\Core\Exception\BadCredentialsException;
use Symfony\Component\Security\Core\Exception\CredentialsExpiredException;

class BlimpProvider implements AuthenticationProviderInterface {
    protected $api;

    private $active_scopes;
    private $active_permissions;

    public function __construct(Container $api) {
        $this->api = $api;
    }

    public function authenticate(TokenInterface $token) {
        $this->all_scopes = [];
        $this->all_permissions = [];

        $credentials = $token->getCredentials();
        if (empty($credentials)) {
            throw new AuthenticationCredentialsNotFoundException();
        }

        $query_builder = $this->api['dataaccess.mongoodm.documentmanager']()->createQueryBuilder();
        $query_builder->eagerCursor(true);
        $query_builder->find('Blimp\Security\Documents\AccessToken');

        $query_builder->field('_id')->equals($credentials);

        $query = $query_builder->getQuery();

        $item = $query->getSingleResult();

        if ($item != null) {
            if ($item->getExpires() != null && $item->getExpires()->getTimestamp() - time() < 0) {
                throw new CredentialsExpiredException();
            }

            $tok = new BlimpToken(explode(' ', $item->getScope()), $this->api['security.roles']);
            $tok->setAccessToken($item);
            $tok->setAuthenticated(true);

            return $tok;
        }

        throw new BadCredentialsException();
    }

    public function supports(TokenInterface $token) {
        return $token instanceof BlimpToken;
    }
}
