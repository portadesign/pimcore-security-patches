<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2024-25625')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class InvitationLinkHostTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5Environment;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5InvitationRequester;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5MailCapture;

    private const ADMIN_USERNAME = 'pd-sec-invite-admin';

    private const INVITEE_USERNAME = 'pd-sec-invite-invitee';

    private const INVITEE_EMAIL = 'invite-recipient@example.test';

    private const DOMAIN = 'invite.example.test';

    private const MAIL_INTRO = "Login to pimcore and change your password using the following link. This temporary login link will expire in  24 hours: \n\n";

    private \Pimcore\Model\User $invitee;

    protected function setUp(): void
    {
        $this->rememberRequestState();
        $this->deleteUserByName(self::ADMIN_USERNAME);
        $this->deleteUserByName(self::INVITEE_USERNAME);
        $admin = $this->createAccount(self::ADMIN_USERNAME, 'invite-admin@example.test', ['users']);
        $this->invitee = $this->createAccount(self::INVITEE_USERNAME, self::INVITEE_EMAIL);
        $this->authenticate($admin);
        $this->setSystemDomain(self::DOMAIN);
        $this->captureMails();
    }

    protected function tearDown(): void
    {
        $this->releaseMails();
        $this->restoreSystemDomain();
        $this->restoreRequestState();
        $this->authenticate(null);
        $this->deleteUserByName(self::ADMIN_USERNAME);
        $this->deleteUserByName(self::INVITEE_USERNAME);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function foreignHostProvider(): array
    {
        return [
            'foreign host' => ['evil.example'],
            'foreign host with port' => ['evil.example:8080'],
            'foreign host with subdomain of the configured one' => ['invite.example.test.evil.example'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('foreignHostProvider')]
    public function testHostHeaderDoesNotSteerTheInvitationLinkOrSubject(string $host): void
    {
        $result = $this->invite(self::INVITEE_USERNAME, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => $host]);

        $this->assertInvitationToConfiguredDomain($result, 'http');
    }

    public function testForwardedHostFromTrustedProxyDoesNotSteerTheInvitationLinkOrSubject(): void
    {
        $this->trustProxyNetwork(
            \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_HOST | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PROTO,
        );

        $result = $this->invite(self::INVITEE_USERNAME, [
            'REMOTE_ADDR' => $this->trustedAddress(),
            'HTTP_HOST' => self::DOMAIN,
            'HTTP_X_FORWARDED_HOST' => 'evil.example',
        ]);

        $this->assertInvitationToConfiguredDomain($result, 'http');
    }

    public function testControlForwardedHostFromUntrustedProxyIsIgnored(): void
    {
        $this->trustProxyNetwork(
            \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_HOST | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PROTO,
        );

        $result = $this->invite(self::INVITEE_USERNAME, [
            'REMOTE_ADDR' => $this->untrustedAddress(),
            'HTTP_HOST' => self::DOMAIN,
            'HTTP_X_FORWARDED_HOST' => 'evil.example',
        ]);

        $this->assertInvitationToConfiguredDomain($result, 'http');
    }

    public function testControlForwardedProtoFromTrustedProxyYieldsHttpsLink(): void
    {
        $this->trustProxyNetwork(
            \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_HOST | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PROTO,
        );

        $result = $this->invite(self::INVITEE_USERNAME, [
            'REMOTE_ADDR' => $this->trustedAddress(),
            'HTTP_HOST' => self::DOMAIN,
            'HTTP_X_FORWARDED_PROTO' => 'https',
        ]);

        $this->assertInvitationToConfiguredDomain($result, 'https');
    }

    public function testControlHostAllowedByTrustedHostsIsKept(): void
    {
        \Symfony\Component\HttpFoundation\Request::setTrustedHosts(['^invite\.example\.test$', '^alt\.example\.test$']);

        $result = $this->invite(self::INVITEE_USERNAME, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => 'alt.example.test']);

        $mail = $this->singleMail();
        $this->assertTrue($result['success'], $result['message']);
        $this->assertSame('Pimcore login invitation for alt.example.test', $mail['subject']);
        $this->assertSame(
            self::MAIL_INTRO . 'http://alt.example.test/admin/login/login?token=' . $this->mailedToken() . '&reset=1',
            $mail['text'],
        );
    }

    public function testNoMailWithoutConfiguredDomainAndTrustedHosts(): void
    {
        $this->setSystemDomain('');

        $result = $this->invite(self::INVITEE_USERNAME, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => 'evil.example']);

        $this->assertFalse($result['success']);
        $this->assertSame([], $this->sentMails);
    }

    /**
     * @param array{success: bool, message: string} $result
     */
    private function assertInvitationToConfiguredDomain(array $result, string $scheme): void
    {
        $mail = $this->singleMail();
        $token = $this->mailedToken();

        $this->assertTrue($result['success'], $result['message']);
        $this->assertSame('Pimcore login invitation for ' . self::DOMAIN, $mail['subject']);
        $this->assertSame(
            self::MAIL_INTRO . $scheme . '://' . self::DOMAIN . '/admin/login/login?token=' . $token . '&reset=1',
            $mail['text'],
        );
        $this->assertSame($this->invitee->getId(), \Pimcore\Tool\Authentication::authenticateToken(urldecode($token))?->getId());
    }

    /**
     * @return array{text: string, html: string, subject: string, recipients: list<string>}
     */
    private function singleMail(): array
    {
        $this->assertCount(1, $this->sentMails, 'exactly one invitation mail must be sent');
        $this->assertSame([self::INVITEE_EMAIL], $this->sentMails[0]['recipients']);

        return $this->sentMails[0];
    }

    private function mailedToken(): string
    {
        return $this->extractToken($this->singleMail()['text']);
    }

    private function extractToken(string $body): string
    {
        $matched = preg_match('~\?token=([^&\s]+)&reset=1$~', $body, $matches);

        return 1 === $matched ? $matches[1] : 'TOKEN-NOT-FOUND-IN-BODY';
    }
}
