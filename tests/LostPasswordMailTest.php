<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-002')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class LostPasswordMailTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5Environment;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5LostPasswordRequester;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5MailCapture;

    private const USERNAME = 'pd-sec-lostpassword-user';

    private const EMAIL = 'lostpassword-recipient@example.test';

    private const DOMAIN = 'lostpassword.example.test';

    private const MAIL_INTRO = "Login to pimcore and change your password using the following link. This temporary login link will expire in 24 hours: \n\n";

    private \Pimcore\Model\User $user;

    protected function setUp(): void
    {
        $this->rememberRequestState();
        \Symfony\Component\HttpFoundation\Request::setTrustedProxies(
            ['2001:db8::/32'],
            $this->originalTrustedHeaderSet | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PREFIX,
        );

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
     * @return array<string, array{string, string}>
     */
    public static function forwardedPrefixProvider(): array
    {
        return [
            'twig expression' => ['{{7*7}}', '{{7*7}}'],
            'twig statement' => ['{% set a = 1 %}x', '{% set a = 1 %}x'],
            'twig filter on empty string' => ["{{ ''|trans }}", "{{ ''|trans }}"],
            'twig comment' => ['{# c #}', '{# c #}'],
            'twig template reference' => ['{{ _self }}', '{{ _self }}'],
            'trailing slash' => ['{{7*7}}/', '{{7*7}}'],
            'only the first of several prefixes counts' => ['{{7*7}},/second', '{{7*7}}'],
            'path prefix with expression' => ['/proxy{{7*7}}', '/proxy{{7*7}}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('forwardedPrefixProvider')]
    public function testForwardedPrefixIsSentLiterallyInTheResetLink(string $header, string $expectedPrefix): void
    {
        $this->assertResetLinkIsMailed($this->trustedAddress(), $header, $expectedPrefix);
    }

    public function testControlPlainForwardedPrefixIsKeptInTheResetLink(): void
    {
        $this->assertResetLinkIsMailed($this->trustedAddress(), '/pim', '/pim');
    }

    public function testControlForwardedPrefixFromUntrustedProxyIsIgnored(): void
    {
        $this->assertResetLinkIsMailed($this->untrustedAddress(), '{{7*7}}', '');
    }

    private function assertResetLinkIsMailed(string $remoteAddress, string $header, string $expectedPrefix): void
    {
        $response = $this->postLostPassword(self::USERNAME, [
            'REMOTE_ADDR' => $remoteAddress,
            'HTTP_HOST' => self::DOMAIN,
            'HTTP_X_FORWARDED_PREFIX' => $header,
        ]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertCount(1, $this->sentMails, 'exactly one reset mail must be sent');
        $this->assertSame([self::EMAIL], $this->sentMails[0]['recipients']);

        $body = $this->sentMails[0]['text'];
        $token = $this->extractResetToken($body);

        $this->assertSame(
            self::MAIL_INTRO . 'http://' . self::DOMAIN . $expectedPrefix . '/admin/login/login?token=' . $token . '&reset=true',
            $body,
        );
        $this->assertSame($this->user->getId(), \Pimcore\Tool\Authentication::authenticateToken(urldecode($token))?->getId());
    }

    private function deleteAccount(): void
    {
        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }
}
