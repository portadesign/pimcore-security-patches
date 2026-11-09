<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait AdminUserSession
{
    protected function authenticate(?\Pimcore\Model\User $user): void
    {
        if (null === $user) {
            $this->tokenStorage()->setToken(null);

            return;
        }

        $proxy = new \Pimcore\Security\User\User($user);
        $this->tokenStorage()->setToken(new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken(
            $proxy,
            'pimcore_admin',
            $proxy->getRoles(),
        ));
    }

    protected function tokenStorage(): \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorageInterface
    {
        $resolver = \Pimcore::getContainer()->get(\Pimcore\Security\User\TokenStorageUserResolver::class);

        return (new \ReflectionProperty($resolver, 'tokenStorage'))->getValue($resolver);
    }

    protected function deleteUserByName(string $name): void
    {
        $existing = \Pimcore\Model\User::getByName($name);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }
}
