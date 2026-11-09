<?php

declare(strict_types=1);

require_once dirname(__DIR__) . '/bootstrap.php';

[, $userId, $method, $path, $destination] = array_pad($argv, 5, '');

$container = \Pimcore::getContainer();

if ('' !== $userId) {
    $user = \Pimcore\Model\User::getById((int) $userId);
    $resolver = $container->get(\Pimcore\Security\User\TokenStorageUserResolver::class);
    $tokenStorage = (new \ReflectionProperty($resolver, 'tokenStorage'))->getValue($resolver);
    $tokenStorage->setToken(new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken(
        new \Pimcore\Security\User\User($user),
        'pimcore_admin',
        [],
    ));
}

$_SERVER['REQUEST_METHOD'] = $method;
$_SERVER['REQUEST_URI'] = $path;
$_SERVER['HTTP_HOST'] = 'localhost';

if ('' !== $destination) {
    $_SERVER['HTTP_DESTINATION'] = $destination;
    $_SERVER['HTTP_OVERWRITE'] = 'T';
}

register_shutdown_function(static function (): void {
    echo "\nHTTP-STATUS:" . http_response_code() . "\n";
});

$controller = new \Pimcore\Bundle\AdminBundle\Controller\Admin\Asset\AssetController();
$controller->setContainer($container);
$controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
$controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));
$controller->webdavAction();
