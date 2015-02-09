<?php
namespace Blimp\Security;

use Pimple\ServiceProviderInterface;
use Blimp\Security\Authentication\BlimpAuthenticationListener;
use Blimp\Security\Authentication\BlimpProvider;
use Blimp\Security\Authorization\BlimpVoter;
use Blimp\Security\Authorization\Permission;
use Blimp\Security\HttpEventSubscriber as HttpEventSubscriber;
use Pimple\Container;
use Symfony\Component\Config\ConfigCache;
use Symfony\Component\Config\Definition\Builder\TreeBuilder;
use Symfony\Component\HttpFoundation\RequestMatcher;
use Symfony\Component\Security\Core\Authentication\AuthenticationProviderManager;
use Symfony\Component\Security\Core\Authentication\Provider\AnonymousAuthenticationProvider;
use Symfony\Component\Security\Core\Authorization\AccessDecisionManager;
use Symfony\Component\Security\Core\SecurityContext;
use Symfony\Component\Security\Core\Exception\AccessDeniedException;
use Symfony\Component\Security\Http\AccessMap;
use Symfony\Component\Security\Http\Firewall;
use Symfony\Component\Security\Http\FirewallMap;
use Symfony\Component\Security\Http\Firewall\AccessListener;
use Symfony\Component\Security\Http\Firewall\AnonymousAuthenticationListener;
use Symfony\Component\Security\Core\Util\SecureRandom;

class SecurityServiceProvider implements ServiceProviderInterface {
    public function register(Container $api) {
        $api['security.random'] = function() {
            return new SecureRandom();
        };

        $api['security.permission.denied'] = $api->protect(function ($scope) {
            throw new AccessDeniedException($scope);
        });

        $api['security.cache'] = __DIR__;

        $api['security.permission.factory'] = $api->protect(function ($domain, $permissions = []) {
            return new Permission($domain, $permissions);
        });

        $api['security.permissions'] = function ($api) {
            return [];
        };

        $api['security.permitions.check'] = $api->protect(function ($domain, $permission) use ($api) {
            if(empty($domain)) {
                return true;
            }

            $token = $api['security']->getToken();

            if(get_class($token) == 'Blimp\\Security\\Authentication\\BlimpToken') {
                $active = $token->getPermissions();

                if(array_key_exists($domain, $active)) {
                    $permissions = $active[$domain]->getPermissions();

                    return in_array($permission, $permissions);
                }
            }

            return false;
        });

        $api['security.roles'] = function ($api) {
            $cachePath = $api['security.cache'] . '/scopes.php';

            $cache = new ConfigCache($cachePath, true);

            $scopes = [];

            $fresh = $cache->isFresh();

            if (!$fresh) {
                $dm = $api['dataaccess.mongoodm.documentmanager']();

                $query_builder = $dm->createQueryBuilder();
                $query_builder->eagerCursor(true);
                $query_builder->find('Blimp\Security\Documents\Scope');

                $query = $query_builder->getQuery();
                $cursor = $query->execute();

                foreach ($cursor as $scope) {
                    $scopes[$scope->getId()] = $scope;
                }

                $scopes = array_merge($scopes, $api['security.permissions']);

                $code = "<?php return " . var_export($scopes, true) . ";";

                $cache->write($code, null);
            } else {
                $scopes = include $cachePath;
            }

            return $scopes;
        };

        $api['security'] = function ($api) {
            return new SecurityContext($api['security.authentication_manager'], $api['security.access_manager']);
        };

        $api['security.authentication_manager'] = function ($api) {
            $manager = new AuthenticationProviderManager($api['security.authentication_providers']);
            $manager->setEventDispatcher($api['http.dispatcher']);

            return $manager;
        };

        $api['security.access_manager'] = function ($api) {
            return new AccessDecisionManager($api['security.voters']);
        };

        $api['security.voters'] = function ($api) {
            return array(
                new BlimpVoter($api)
            );
        };

        $api['security.firewall'] = function ($api) {
            return new Firewall($api['security.firewall_map'], $api['http.dispatcher']);
        };

        $api['security.authentication_listener.factory.blimp'] = $api->protect(function ($name, $options) use ($api) {
            $api['security.authentication_listener.' . $name . '.blimp'] = function ($api) use ($name, $options) {
                return new BlimpAuthenticationListener($api, $api['security'], $api['security.authentication_manager']);
            };

            $api['security.authentication_provider.' . $name . '.blimp'] = function ($api) {
                return new BlimpProvider($api);
            };

            return array(
                'security.authentication_provider.' . $name . '.blimp',
                'security.authentication_listener.' . $name . '.blimp',
            );
        });

        $api['security.authentication_listener.factory.anonymous'] = $api->protect(function ($name, $options) use ($api) {
            $api['security.authentication_listener.' . $name . '.anonymous'] = function ($api) use ($name, $options) {
                return new AnonymousAuthenticationListener(
                    $api['security'],
                    $name,
                    $api['blimp.logger']
                );
            };

            $api['security.authentication_provider.' . $name . '.anonymous'] = function ($api) use ($name) {
                return new AnonymousAuthenticationProvider($name);
            };

            return array(
                'security.authentication_provider.' . $name . '.anonymous',
                'security.authentication_listener.' . $name . '.anonymous',
            );
        });

        $api['security.firewall_map'] = function ($api) {
            $providers = array();
            $configs = array();

            if (($firewalls = $api['config']['security']['firewalls']) != null) {
                foreach ($firewalls as $name => $firewall) {
                    $pattern = isset($firewall['pattern']) ? $firewall['pattern'] : null;
                    $security = isset($firewall['security']) ? (bool) $firewall['security'] : true;
                    $anonymous = isset($firewall['anonymous']) ? (bool) $firewall['anonymous'] : true;

                    $listeners = [];

                    if ($security) {
                        $options = array();
                        if (!empty($firewall['options'])) {
                            if (is_array($firewall['options'])) {
                                $options = $firewall['options'];
                            }
                        }

                        list($providerId, $listenerId) = $api['security.authentication_listener.factory.blimp']($name, $options);

                        $providers[] = $providerId;
                        $listeners[] = $listenerId;

                        if ($anonymous) {
                            list($providerId, $listenerId) = $api['security.authentication_listener.factory.anonymous']($name, $options);

                            $providers[] = $providerId;
                            $listeners[] = $listenerId;
                        }

                        $listeners[] = 'security.access_listener';
                    }

                    $configs[$name] = array($pattern, $listeners, $security);
                }
            }

            $api['security.authentication_providers'] = array_map(function ($provider) use ($api) {
                return $api[$provider];
            }, array_unique($providers));

            $map = new FirewallMap();
            foreach ($configs as $config) {
                $map->add(
                    is_string($config[0]) ? new RequestMatcher($config[0]) : $config[0],
                    array_map(function ($listenerId) use ($api) {
                        $listener = $api[$listenerId];
                        return $listener;
                    }, $config[1])
                );
            }

            return $map;
        };

        $api['security.access_listener'] = function ($api) {
            return new AccessListener(
                $api['security'],
                $api['security.access_manager'],
                $api['security.access_map'],
                $api['security.authentication_manager'],
                $api['blimp.logger']
            );
        };

        $api['security.access_map'] = function ($api) {
            $map = new AccessMap();

            if (($access_control = $api['config']['security']['access_control']) != null) {
                foreach ($access_control as $access) {
                    $matcher = new RequestMatcher(
                        $access['path'],
                        $access['host'],
                        $access['methods'],
                        $access['ips']
                    );

                    $map->add($matcher, $access['roles'], $access['requires_channel']);
                }
            }

            return $map;
        };

        $api['security.http.listener'] = function ($api) {
            return new HttpEventSubscriber($api);
        };

        $api->extend('blimp.extend', function ($status, $api) {
            if($status) {
                if($api->offsetExists('security.permissions')) {
                    $api->extend('security.permissions', function ($permissions, $api) {
                        $permissions['auth'] = $api['security.permission.factory']('auth', ['create', 'list', 'get', 'edit', 'delete']);

                        return $permissions;
                    });
                }

                if ($api->offsetExists('dataaccess.mongoodm.mappings')) {
                    $api->extend('dataaccess.mongoodm.mappings', function ($mappings, $api) {
                        $mappings[] = ['dir' => __DIR__ . '/Documents', 'prefix' => 'Blimp\\Security\\Documents\\'];

                        return $mappings;
                    });
                }

                if ($api->offsetExists('config.root')) {
                    $api->extend('config.root', function ($root, $api) {
                        $tb = new TreeBuilder();

                        $rootNode = $tb->root('security');

                        $rootNode
                            ->fixXmlConfig('firewall')
                        ->children()
                            ->arrayNode('firewalls')
                        ->isRequired()
                            ->requiresAtLeastOneElement()
                        ->disallowNewKeysInSubsequentConfigs()
                            ->useAttributeAsKey('name')
                        ->prototype('array')
                            ->children()
                        ->scalarNode('pattern')->end()
                        ->booleanNode('security')->defaultTrue()->end()
                            ->booleanNode('anonymous')->defaultTrue()->end()
                        ->end()
                            ->end();

                        $rootNode
                            ->fixXmlConfig('rule', 'access_control')
                        ->children()
                            ->arrayNode('access_control')
                        ->cannotBeOverwritten()
                            ->prototype('array')
                        ->fixXmlConfig('ip')
                            ->children()
                        ->scalarNode('requires_channel')->defaultNull()->end()
                            ->scalarNode('path')
                        ->defaultNull()
                            ->info('use the urldecoded format')
                        ->example('^/path to resource/')
                            ->end()
                        ->scalarNode('host')->defaultNull()->end()
                            ->arrayNode('ips')
                        ->beforeNormalization()->ifString()->then(function ($v) {return array($v);})->end()
                        ->prototype('scalar')->end()
                        ->end()
                            ->arrayNode('methods')
                        ->beforeNormalization()->ifString()->then(function ($v) {return preg_split('/\s*,\s*/', $v);})->end()
                        ->prototype('scalar')->end()
                        ->end()
                            ->scalarNode('allow_if')->defaultNull()->end()
                        ->end()
                            ->fixXmlConfig('role')
                        ->children()
                            ->arrayNode('roles')
                        ->beforeNormalization()->ifString()->then(function ($v) {return preg_split('/\s* \s*/', $v);})->end()
                        ->prototype('scalar')->end()
                        ->end()
                            ->end()
                        ->end()
                            ->end()
                        ->end();

                        $rootNode
                            ->fixXmlConfig('role', 'role_hierarchy')
                        ->children()
                            ->arrayNode('role_hierarchy')
                        ->useAttributeAsKey('id')
                            ->prototype('array')
                        ->performNoDeepMerging()
                            ->beforeNormalization()->ifString()->then(function ($v) {return array('value' => $v);})->end()
                        ->beforeNormalization()
                            ->ifTrue(function ($v) {return is_array($v) && isset($v['value']);})
                            ->then(function ($v) {return preg_split('/\s*,\s*/', $v['value']);})
                            ->end()
                        ->prototype('scalar')->end()
                        ->end()
                            ->end()
                        ->end()
                        ;

                        $root->append($rootNode);

                        return $root;
                    });
                }

                $api->extend('blimp.init', function ($status, $api) {
                    if ($status) {
                        $api['http.dispatcher']->addSubscriber($api['security.firewall']);
                        $api['http.dispatcher']->addSubscriber($api['security.http.listener']);
                    }

                    return $status;
                });
            }

            return $status;
        });
    }
}
