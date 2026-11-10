<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-002')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class InvitationMailTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5Environment;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5InvitationRequester;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5MailCapture;

    private const ADMIN_USERNAME = 'pd-sec-invitemail-admin';

    private const INVITEE_USERNAME = 'pd-sec-invitemail-invitee';

    private const INVITEE_EMAIL = 'invitemail-recipient@example.test';

    private const DOMAIN = 'invitemail.example.test';

    private const MAIL_INTRO = "Login to pimcore and change your password using the following link. This temporary login link will expire in  24 hours: \n\n";

    private \Pimcore\Model\User $invitee;

    protected function setUp(): void
    {
        $this->rememberRequestState();
        \Symfony\Component\HttpFoundation\Request::setTrustedProxies(
            ['2001:db8::/32'],
            $this->originalTrustedHeaderSet | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PREFIX,
        );

        $this->deleteUserByName(self::ADMIN_USERNAME);
        $this->deleteUserByName(self::INVITEE_USERNAME);
        $admin = $this->createAccount(self::ADMIN_USERNAME, 'invitemail-admin@example.test', ['users']);
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
     * @return array<string, array{string, string}>
     */
    public static function forwardedPrefixProvider(): array
    {
        return [
            'twig expression' => ['{{7*7}}', '{{7*7}}'],
            'twig statement' => ['{% set a = 1 %}x', '{% set a = 1 %}x'],
            'twig comment' => ['{# c #}', '{# c #}'],
            'path prefix with expression' => ['/proxy{{7*7}}', '/proxy{{7*7}}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('forwardedPrefixProvider')]
    public function testForwardedPrefixIsSentLiterallyInTheInvitationLink(string $header, string $expectedPrefix): void
    {
        $this->assertInvitationIsMailed($this->trustedAddress(), $header, $expectedPrefix);
    }

    public function testControlPlainForwardedPrefixIsKeptInTheInvitationLink(): void
    {
        $this->assertInvitationIsMailed($this->trustedAddress(), '/pim', '/pim');
    }

    public function testControlForwardedPrefixFromUntrustedProxyIsIgnored(): void
    {
        $this->assertInvitationIsMailed($this->untrustedAddress(), '{{7*7}}', '');
    }

    private function assertInvitationIsMailed(string $remoteAddress, string $header, string $expectedPrefix): void
    {
        $result = $this->invite(self::INVITEE_USERNAME, [
            'REMOTE_ADDR' => $remoteAddress,
            'HTTP_HOST' => self::DOMAIN,
            'HTTP_X_FORWARDED_PREFIX' => $header,
        ]);

        $this->assertTrue($result['success'], $result['message']);
        $this->assertCount(1, $this->sentMails, 'exactly one invitation mail must be sent');
        $this->assertSame([self::INVITEE_EMAIL], $this->sentMails[0]['recipients']);

        $body = $this->sentMails[0]['text'];
        $matched = preg_match('~\?token=([^&\s]+)&reset=1$~', $body, $matches);
        $token = 1 === $matched ? $matches[1] : 'TOKEN-NOT-FOUND-IN-BODY';

        $this->assertSame(
            self::MAIL_INTRO . 'http://' . self::DOMAIN . $expectedPrefix . '/admin/login/login?token=' . $token . '&reset=1',
            $body,
        );
        $this->assertSame($this->invitee->getId(), \Pimcore\Tool\Authentication::authenticateToken(urldecode($token))?->getId());
    }
}
