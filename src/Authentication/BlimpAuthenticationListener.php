<?php
namespace Blimp\Security\Authentication;

use Blimp\Security\Authentication\BlimpToken as BlimpToken;
use Pimple\Container;
use Symfony\Component\HttpKernel\Event\GetResponseEvent;
use Symfony\Component\Security\Core\Authentication\AuthenticationManagerInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Core\SecurityContextInterface;
use Symfony\Component\Security\Http\Firewall\ListenerInterface;

class BlimpAuthenticationListener implements ListenerInterface {
    protected $api;

    protected $securityContext;
    protected $authenticationManager;

    public function __construct(Container $api, SecurityContextInterface $securityContext, AuthenticationManagerInterface $authenticationManager) {
        $this->api = $api;

        $this->securityContext = $securityContext;
        $this->authenticationManager = $authenticationManager;
    }

    public function handle(GetResponseEvent $event) {
        if (null !== $token = $this->securityContext->getToken()) {
            if ($token instanceof BlimpToken && $token->isAuthenticated()) {
                return;
            }
        }

        $request = $event->getRequest();

        $auth = null;
        if ($request->headers->has('authorization')) {
            $auth = $request->headers->get('authorization');
        } else if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
            $auth = $_SERVER['HTTP_AUTHORIZATION'];
        } else if (isset($_SERVER['PHP_AUTH_DIGEST'])) {
            $auth = $_SERVER['PHP_AUTH_DIGEST'];
        }

        $access_token = null;
        if (!empty($auth) && preg_match('/^Bearer (.+)/', $auth, $matches) === 1) {
            $access_token = $matches[1];
        } else if ($request->query->has('access_token')) {
            $access_token = $request->query->get('access_token');
            $request->query->remove('access_token');
        } else {
            return;
        }

        $this->api['blimp.logger']->log('info', 'Access token found');

        try {
            $unauthenticatedToken = new BlimpToken();
            $unauthenticatedToken->setCredentials($access_token);

            $authenticatedToken = $this->authenticationManager->authenticate($unauthenticatedToken);
            $this->securityContext->setToken($authenticatedToken);
        } catch (AuthenticationException $failed) {
            $token = $this->securityContext->getToken();
            if ($token != null && $token instanceof BlimpToken) {
                $this->securityContext->setToken(null);
            }

            $this->api['blimp.logger']->log('info', sprintf('Authentication request failed for provided access token: %s', $failed->getMessageKey()));

            throw $failed;
        }
    }
}
