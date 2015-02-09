<?php
namespace Blimp\Security\Rest;

use Blimp\Http\BlimpHttpException;
use Pimple\Container;
use Blimp\DataAccess\Rest\MongoODMCollection;
use Blimp\Security\Documents\Client;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Clients {
    public function process(Container $api, Request $request, $_securityDomain = null, $_resourceClass = null, $_idField = null, $_idLowercase = true) {
        $_resourceClass = 'Blimp\Security\Documents\Client';
        $_securityDomain = 'auth';

        if ($request->getMethod() == 'POST') {
            $can_create = $api['security.permitions.check']($_securityDomain, 'create');

            if(!$can_create) {
                $api['security.permission.denied']($_securityDomain.':create');
            }

            $data = $request->attributes->get('data');

            $item = new Client();
            $api['dataaccess.mongoodm.utils']->convertToBlimpDocument($data, $item);

            $item->setSecret(base64_encode($api['security.random']->nextBytes(20)));

            $dm = $api['dataaccess.mongoodm.documentmanager']();
            $dm->persist($item);
            $dm->flush();

            $resource_uri = $request->getPathInfo() . '/' . $item->getId();

            $response = new JsonResponse((object) ["uri" => $resource_uri], Response::HTTP_CREATED);
            $response->headers->set('Location', $resource_uri);

            return $response;
        } else {
            throw new BlimpHttpException(Response::HTTP_METHOD_NOT_ALLOWED, "Method not allowed");
        }
    }
}
