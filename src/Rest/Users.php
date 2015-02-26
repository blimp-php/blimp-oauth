<?php
namespace Blimp\Security\Rest;

use Blimp\Http\BlimpHttpException;
use Pimple\Container;
use Blimp\DataAccess\Rest\MongoODMCollection;
use Blimp\Security\Documents\ResourceOwner;
use Blimp\Security\Documents\ResourceOwnerActivity;
use Blimp\Security\Documents\ResourceOwnerCredentials;
use Blimp\Security\Documents\User;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;

class Users {
    public function process(Container $api, Request $request, $_securityDomain = null, $_resourceClass = null, $_idField = null, $_idLowercase = true) {
        $_resourceClass = 'Blimp\Security\Documents\User';
        $_securityDomain = 'users';
        $_idField = 'username';
        $_idLowercase = true;

        if ($request->getMethod() == 'POST') {
            $can_create = $api['security.permitions.check']($_securityDomain, 'create');

            if(!$can_create) {
                $api['security.permission.denied']($_securityDomain.':create');
            }

            $data = $request->attributes->get('data');

            if (empty($data[$_idField])) {
                throw new BlimpHttpException(Response::HTTP_BAD_REQUEST, "'$_idField' is mandatory");
            } else {
                $id = $data[$_idField];
                if ($_idLowercase) {
                    $id = strtolower($id);
                    $data[$_idField] = $id;
                }

                $data['id'] = $id;

                $dm = $api['dataaccess.mongoodm.documentmanager']();

                $check = $dm->find($_resourceClass, $id);

                if ($check != null) {
                    throw new BlimpHttpException(Response::HTTP_CONFLICT, "Duplicate Id", "Id strategy set to NONE and provided Id already exists");
                }

                $user = new User();
                $user->setId($id);
                $user->setName($data['name']);
                if(array_key_exists('email', $data)) {
                    $user->setEmail($data['email']);
                }
                if(array_key_exists('gender', $data)) {
                    $user->setGender($data['gender']);
                }
                $dm->persist($user);

                $credentials = new ResourceOwnerCredentials();
                $credentials->setUsername($id);
                $credentials->setPassword(password_hash($data['password'], PASSWORD_DEFAULT));
                $dm->persist($credentials);

                $activity = new ResourceOwnerActivity();
                $activity->setAction('Created');
                $dm->persist($activity);

                $owner = new ResourceOwner();
                $owner->setProfile($user);
                $owner->addCredentials($credentials);
                $owner->addActivity($activity);

                $owner->setScopes($data['scopes']);

                $dm->persist($owner);

                $dm->flush();

                $resource_uri = $request->getPathInfo() . '/' . $id;

                $response = new JsonResponse((object) ["uri" => $resource_uri], Response::HTTP_CREATED);
                $response->headers->set('Location', $resource_uri);

                return $response;
            }
        } else {
            throw new BlimpHttpException(Response::HTTP_METHOD_NOT_ALLOWED, "Method not allowed e");
        }
    }
}
