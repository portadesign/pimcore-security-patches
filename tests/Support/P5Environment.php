<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait P5Environment
{
    private ?array $originalGeneralSettings = null;

    /**
     * @var list<string>
     */
    private array $originalTrustedProxies = [];

    private int $originalTrustedHeaderSet = 0;

    /**
     * @var list<string>
     */
    private array $originalTrustedHosts = [];

    protected function rememberRequestState(): void
    {
        $this->originalTrustedProxies = \Symfony\Component\HttpFoundation\Request::getTrustedProxies();
        $this->originalTrustedHeaderSet = \Symfony\Component\HttpFoundation\Request::getTrustedHeaderSet();
        $this->originalTrustedHosts = \Symfony\Component\HttpFoundation\Request::getTrustedHosts();
    }

    protected function restoreRequestState(): void
    {
        \Symfony\Component\HttpFoundation\Request::setTrustedProxies($this->originalTrustedProxies, $this->originalTrustedHeaderSet);
        \Symfony\Component\HttpFoundation\Request::setTrustedHosts($this->originalTrustedHosts);
    }

    protected function trustProxyNetwork(int $headers): void
    {
        \Symfony\Component\HttpFoundation\Request::setTrustedProxies(['2001:db8::/32'], $headers);
    }

    protected function setSystemDomain(string $domain): void
    {
        $general = \Pimcore\Config::getSystemConfiguration('general') ?? [];
        $this->originalGeneralSettings ??= $general;
        \Pimcore\Config::setSystemConfiguration(array_merge($general, ['domain' => $domain]), 'general');
    }

    protected function restoreSystemDomain(): void
    {
        if (null !== $this->originalGeneralSettings) {
            \Pimcore\Config::setSystemConfiguration($this->originalGeneralSettings, 'general');
            $this->originalGeneralSettings = null;
        }
    }

    protected function trustedAddress(): string
    {
        return $this->randomAddress('2001:db8');
    }

    protected function untrustedAddress(): string
    {
        return $this->randomAddress('2001:db9');
    }

    private function randomAddress(string $networkPrefix): string
    {
        return sprintf('%s::%x:%x', $networkPrefix, random_int(1, 0xFFFF), random_int(1, 0xFFFF));
    }

    /**
     * @param list<string> $permissions
     */
    protected function createAccount(string $name, ?string $email, array $permissions = [], ?string $passwordHash = null, bool $active = true): \Pimcore\Model\User
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => $name,
            'email' => $email,
            'password' => $passwordHash ?? password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => $active,
            'admin' => false,
        ]);
        $user->setPermissions($permissions);
        $user->save();

        return $user;
    }

    protected function adminController(string $class): object
    {
        $container = \Pimcore::getContainer();

        if ($container->has($class)) {
            return $container->get($class);
        }

        $controller = new $class();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));

        return $controller;
    }
}
