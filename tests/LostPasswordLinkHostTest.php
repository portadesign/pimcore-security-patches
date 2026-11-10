<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2024-23648')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class LostPasswordLinkHostTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5Environment;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5LostPasswordRequester;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5MailCapture;

    private const USERNAME = 'pd-sec-lostlink-user';

    private const EMAIL = 'lostlink-recipient@example.test';

    private const DOMAIN = 'lostlink.example.test';

    private const MAIL_INTRO = "Login to pimcore and change your password using the following link. This temporary login link will expire in 24 hours: \n\n";

    private \Pimcore\Model\User $user;

    protected function setUp(): void
    {
        $this->rememberRequestState();
        $this->deleteAccount();
        $this->user = $this->createAccount(self::USERNAME, self::EMAIL);
        $this->setSystemDomain(self::DOMAIN);
        $this->captureMails();
    }

    protected function tearDown(): void
    {
        $this->releaseMails();
        $this->restoreSystemDomain();
        $this->restoreRequestState();
        $this->deleteAccount();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function foreignHostProvider(): array
    {
        return [
            'foreign host' => ['evil.example'],
            'foreign host with port' => ['evil.example:8080'],
            'foreign host with subdomain of the configured one' => ['lostlink.example.test.evil.example'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('foreignHostProvider')]
    public function testHostHeaderDoesNotSteerTheResetLink(string $host): void
    {
        $response = $this->postLostPassword(self::USERNAME, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => $host]);

        $this->assertResetLinkToConfiguredDomain($response, 'http');
    }

    public function testForwardedHostFromTrustedProxyDoesNotSteerTheResetLink(): void
    {
        $this->trustProxyNetwork(
            \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_HOST | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PROTO,
        );

        $response = $this->postLostPassword(self::USERNAME, [
            'REMOTE_ADDR' => $this->trustedAddress(),
            'HTTP_HOST' => self::DOMAIN,
            'HTTP_X_FORWARDED_HOST' => 'evil.example',
        ]);

        $this->assertResetLinkToConfiguredDomain($response, 'http');
    }

    public function testControlForwardedHostFromUntrustedProxyIsIgnored(): void
    {
        $this->trustProxyNetwork(
            \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_HOST | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PROTO,
        );

        $response = $this->postLostPassword(self::USERNAME, [
            'REMOTE_ADDR' => $this->untrustedAddress(),
            'HTTP_HOST' => self::DOMAIN,
            'HTTP_X_FORWARDED_HOST' => 'evil.example',
        ]);

        $this->assertResetLinkToConfiguredDomain($response, 'http');
    }

    public function testControlForwardedProtoFromTrustedProxyYieldsHttpsLink(): void
    {
        $this->trustProxyNetwork(
            \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_HOST | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PROTO,
        );

        $response = $this->postLostPassword(self::USERNAME, [
            'REMOTE_ADDR' => $this->trustedAddress(),
            'HTTP_HOST' => self::DOMAIN,
            'HTTP_X_FORWARDED_PROTO' => 'https',
        ]);

        $this->assertResetLinkToConfiguredDomain($response, 'https');
    }

    public function testControlHostAllowedByTrustedHostsIsKept(): void
    {
        \Symfony\Component\HttpFoundation\Request::setTrustedHosts(['^lostlink\.example\.test$', '^alt\.example\.test$']);

        $response = $this->postLostPassword(self::USERNAME, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => 'alt.example.test']);

        $this->assertNeutralResult($response);
        $this->assertSame(
            self::MAIL_INTRO . 'http://alt.example.test/admin/login/login?token=' . $this->mailedToken() . '&reset=true',
            $this->singleMail()['text'],
        );
        $this->assertSame($this->user->getId(), \Pimcore\Tool\Authentication::authenticateToken(urldecode($this->mailedToken()))?->getId());
    }

    public function testPortOfATrustedHostIsNotCarriedIntoTheLink(): void
    {
        \Symfony\Component\HttpFoundation\Request::setTrustedHosts(['^lostlink\.example\.test$', '^allowed\.example$']);

        $response = $this->postLostPassword(self::USERNAME, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => 'allowed.example:4444']);

        $this->assertNeutralResult($response);
        $this->assertSame(
            self::MAIL_INTRO . 'http://allowed.example/admin/login/login?token=' . $this->mailedToken() . '&reset=true',
            $this->singleMail()['text'],
        );
    }

    public function testControlTrustedHostIsUsedWithoutConfiguredDomain(): void
    {
        $this->setSystemDomain('');
        \Symfony\Component\HttpFoundation\Request::setTrustedHosts(['^alt\.example\.test$']);

        $response = $this->postLostPassword(self::USERNAME, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => 'alt.example.test']);

        $this->assertNeutralResult($response);
        $this->assertSame(
            self::MAIL_INTRO . 'http://alt.example.test/admin/login/login?token=' . $this->mailedToken() . '&reset=true',
            $this->singleMail()['text'],
        );
    }

    public function testNoMailWithoutConfiguredDomainAndTrustedHosts(): void
    {
        $this->setSystemDomain('');

        $response = $this->postLostPassword(self::USERNAME, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => 'evil.example']);

        $this->assertNeutralResult($response);
        $this->assertSame([], $this->sentMails);
    }

    private function assertResetLinkToConfiguredDomain(\Symfony\Component\HttpFoundation\Response $response, string $scheme): void
    {
        $this->assertNeutralResult($response);

        $token = $this->mailedToken();
        $this->assertSame(
            self::MAIL_INTRO . $scheme . '://' . self::DOMAIN . '/admin/login/login?token=' . $token . '&reset=true',
            $this->singleMail()['text'],
        );
        $this->assertSame($this->user->getId(), \Pimcore\Tool\Authentication::authenticateToken(urldecode($token))?->getId());
    }

    private function assertNeutralResult(\Symfony\Component\HttpFoundation\Response $response): void
    {
        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString('class="text success"', (string) $response->getContent());
        $this->assertStringNotContainsString('class="text error"', (string) $response->getContent());
    }

    /**
     * @return array{text: string, html: string, subject: string, recipients: list<string>}
     */
    private function singleMail(): array
    {
        $this->assertCount(1, $this->sentMails, 'exactly one reset mail must be sent');
        $this->assertSame([self::EMAIL], $this->sentMails[0]['recipients']);

        return $this->sentMails[0];
    }

    private function mailedToken(): string
    {
        return $this->extractResetToken($this->singleMail()['text']);
    }

    private function deleteAccount(): void
    {
        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }
}
