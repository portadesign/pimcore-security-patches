<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests\Support;

trait P5LostPasswordRequester
{
    /**
     * @param array<string, string> $server
     * @param array<string, object> $attributes
     */
    protected function postLostPassword(string $username, array $server, array $attributes = []): \Symfony\Component\HttpFoundation\Response
    {
        $kernel = \Pimcore::getKernel();
        \assert($kernel instanceof \Symfony\Component\HttpKernel\HttpKernelInterface);

        $tokenResponse = $kernel->handle(\Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/login/csrf-token',
            method: 'GET',
            server: $server,
        ));
        $this->assertSame(200, $tokenResponse->getStatusCode(), 'csrf token endpoint must answer');

        $cookies = [];
        foreach ($tokenResponse->headers->getCookies() as $cookie) {
            $cookies[$cookie->getName()] = (string) $cookie->getValue();
        }
        $csrfToken = json_decode((string) $tokenResponse->getContent(), true, flags: JSON_THROW_ON_ERROR)['csrfToken'];

        $request = \Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/login/lostpassword',
            method: 'POST',
            parameters: ['username' => $username, 'csrfToken' => $csrfToken],
            cookies: $cookies,
            server: $server,
        );
        foreach ($attributes as $name => $value) {
            $request->attributes->set($name, $value);
        }

        return $kernel->handle($request);
    }

    protected function extractResetToken(string $body): string
    {
        $matched = preg_match('~\?token=([^&\s]+)&reset=(?:true|1)$~', $body, $matches);

        return 1 === $matched ? $matches[1] : 'TOKEN-NOT-FOUND-IN-BODY';
    }
}
