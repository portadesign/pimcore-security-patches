<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115898')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class LostPasswordMailTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MailCapture;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\MainDomainFixture;

    private const USERNAME = 'pd-sec-lostpassword-user';

    private const PROXY_NETWORK = '2001:db8::/32';

    private const MAIL_INTRO = "Login to pimcore and change your password using the following link. This temporary login link will expire in 24 hours: \n\n";

    private \Pimcore\Model\User $user;

    /**
     * @var list<string>
     */
    private array $originalTrustedProxies = [];

    private int $originalTrustedHeaderSet = 0;

    protected function setUp(): void
    {
        $this->originalTrustedProxies = \Symfony\Component\HttpFoundation\Request::getTrustedProxies();
        $this->originalTrustedHeaderSet = \Symfony\Component\HttpFoundation\Request::getTrustedHeaderSet();
        \Symfony\Component\HttpFoundation\Request::setTrustedProxies(
            [self::PROXY_NETWORK],
            $this->originalTrustedHeaderSet | \Symfony\Component\HttpFoundation\Request::HEADER_X_FORWARDED_PREFIX,
        );

        $this->ensureDomain();
        $this->deleteUser();

        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'email' => 'lostpassword-recipient@example.test',
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
        ]);
        $this->startCapturingMails();
    }

    protected function tearDown(): void
    {
        $this->stopCapturingMails();

        \Symfony\Component\HttpFoundation\Request::setTrustedProxies($this->originalTrustedProxies, $this->originalTrustedHeaderSet);
        $this->restoreDomain();
        $this->deleteUser();
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
        $this->assertResetLinkIsMailed($this->randomAddress('2001:db9'), '{{7*7}}', '');
    }

    private function assertResetLinkIsMailed(string $remoteAddress, string $header, string $expectedPrefix): void
    {
        $response = $this->requestReset($remoteAddress, $header);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertCount(1, $this->sentMails, 'exactly one reset mail must be sent');
        $this->assertSame(['lostpassword-recipient@example.test'], $this->sentMails[0]['recipients']);

        $body = $this->sentMails[0]['text'];
        $token = $this->extractToken($body);

        $this->assertSame(
            self::MAIL_INTRO . 'http://' . $this->domain . $expectedPrefix . '/admin/login/login?token=' . $token . '&reset=true',
            $body,
        );
        $this->assertSame($this->user->getId(), \Pimcore\Tool\Authentication::authenticateToken(urldecode($token))?->getId());
    }

    private function trustedAddress(): string
    {
        return $this->randomAddress('2001:db8');
    }

    private function randomAddress(string $networkPrefix): string
    {
        return sprintf('%s::%x:%x', $networkPrefix, random_int(1, 0xFFFF), random_int(1, 0xFFFF));
    }

    private function requestReset(string $remoteAddress, string $forwardedPrefix): \Symfony\Component\HttpFoundation\Response
    {
        $kernel = \Pimcore::getKernel();
        \assert($kernel instanceof \Symfony\Component\HttpKernel\HttpKernelInterface);

        $tokenResponse = $kernel->handle(\Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/login/csrf-token',
            method: 'GET',
            server: ['REMOTE_ADDR' => $remoteAddress],
        ));
        $this->assertSame(200, $tokenResponse->getStatusCode(), 'csrf token endpoint must answer');

        $cookies = [];
        foreach ($tokenResponse->headers->getCookies() as $cookie) {
            $cookies[$cookie->getName()] = (string) $cookie->getValue();
        }
        $csrfToken = json_decode((string) $tokenResponse->getContent(), true, flags: JSON_THROW_ON_ERROR)['csrfToken'];

        return $kernel->handle(\Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/login/lostpassword',
            method: 'POST',
            parameters: ['username' => self::USERNAME, 'csrfToken' => $csrfToken],
            cookies: $cookies,
            server: ['REMOTE_ADDR' => $remoteAddress, 'HTTP_X_FORWARDED_PREFIX' => $forwardedPrefix],
        ));
    }

    private function extractToken(string $body): string
    {
        $matched = preg_match('~\?token=([^&\s]+)&reset=true$~', $body, $matches);

        return 1 === $matched ? $matches[1] : 'TOKEN-NOT-FOUND-IN-BODY';
    }

    private function deleteUser(): void
    {
        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }
}
