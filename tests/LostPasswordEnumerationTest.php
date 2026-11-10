<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2025-24980')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class LostPasswordEnumerationTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5Environment;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5LostPasswordRequester;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5MailCapture;

    private const KNOWN = 'pd-sec-enum-known';

    private const INACTIVE = 'pd-sec-enum-inactive';

    private const NO_EMAIL = 'pd-sec-enum-noemail';

    private const NO_PASSWORD = 'pd-sec-enum-nopassword';

    private const UNKNOWN = 'pd-sec-enum-unknown';

    private const MAILFAIL = 'pd-sec-enum-mailfail';

    private const DOMAIN = 'enum.example.test';

    private const KNOWN_EMAIL = 'enum-known@example.test';

    private ?string $logFile = null;

    protected function setUp(): void
    {
        $this->rememberRequestState();
        $this->deleteAccounts();
        $this->createAccount(self::KNOWN, self::KNOWN_EMAIL);
        $this->createAccount(self::INACTIVE, 'enum-inactive@example.test', active: false);
        $this->createAccount(self::NO_EMAIL, null);
        $this->createAccount(self::MAILFAIL, 'enum-mailfail@example.test');
        $noPassword = $this->createAccount(self::NO_PASSWORD, 'enum-nopassword@example.test');
        \Pimcore\Db::get()->update('users', ['password' => null], ['id' => $noPassword->getId()]);
        $this->setSystemDomain(self::DOMAIN);
        $this->captureMails();
    }

    protected function tearDown(): void
    {
        $this->releaseMails();
        $this->restoreSystemDomain();
        $this->restoreRequestState();
        $this->deleteAccounts();

        if (null !== $this->logFile && is_file($this->logFile)) {
            unlink($this->logFile);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function indistinguishableOutcomeProvider(): array
    {
        return [
            'unknown user' => [self::UNKNOWN],
            'inactive user' => [self::INACTIVE],
            'user without email' => [self::NO_EMAIL],
            'user without password' => [self::NO_PASSWORD],
            'mail sending fails' => [self::MAILFAIL],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('indistinguishableOutcomeProvider')]
    public function testOutcomeIsIndistinguishableFromAKnownUser(string $username): void
    {
        $known = $this->postLostPassword(self::KNOWN, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => self::DOMAIN]);
        $this->assertCount(1, $this->sentMails);
        $this->assertSame([self::KNOWN_EMAIL], $this->sentMails[0]['recipients']);

        $failing = static function (): void {
            throw new \RuntimeException('mail transport down');
        };
        if (self::MAILFAIL === $username) {
            \Pimcore::getEventDispatcher()->addListener(\Pimcore\Bundle\AdminBundle\Event\AdminEvents::LOGIN_LOSTPASSWORD, $failing);
        }

        try {
            $other = $this->postLostPassword($username, ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => self::DOMAIN]);
        } finally {
            \Pimcore::getEventDispatcher()->removeListener(\Pimcore\Bundle\AdminBundle\Event\AdminEvents::LOGIN_LOSTPASSWORD, $failing);
        }

        $this->assertSame($known->getStatusCode(), $other->getStatusCode());
        $this->assertFalse(str_contains((string) $other->getContent(), 'class="text error"'), 'response for ' . $username . ' shows an error block');
        $this->assertSame($this->resultBlock($known), $this->resultBlock($other));
        $this->assertCount(1, $this->sentMails, 'only the active user with an email address receives a mail');
    }

    public function testControlRateLimitAnswersKnownAndUnknownUsersAlike(): void
    {
        $known = $this->exhaustRateLimit(self::KNOWN);
        $unknown = $this->exhaustRateLimit(self::UNKNOWN);

        $this->assertSame(6, $known['attempt']);
        $this->assertSame(6, $unknown['attempt']);
        $this->assertSame($known['block'], $unknown['block']);
        $this->assertStringContainsString('Too many attempts', $known['block']);
    }

    public function testLegacyBruteforceLogRecordsARequestForAKnownUser(): void
    {
        $this->assertLegacyLogHasOneEntryFor(self::KNOWN);
    }

    public function testControlLegacyBruteforceLogRecordsARequestForAnUnknownUser(): void
    {
        $this->assertLegacyLogHasOneEntryFor(self::UNKNOWN);
    }

    private function assertLegacyLogHasOneEntryFor(string $username): void
    {
        $this->logFile = sys_get_temp_dir() . '/pd-sec-enum-' . bin2hex(random_bytes(6)) . '.log';
        $handler = new \Pimcore\Bundle\AdminBundle\Security\BruteforceProtectionHandler(
            \Pimcore::getContainer()->get(\Pimcore\Http\RequestHelper::class),
            $this->logFile,
        );
        $handler->setLogger(new \Psr\Log\NullLogger());

        $this->postLostPassword(
            $username,
            ['REMOTE_ADDR' => $this->untrustedAddress(), 'HTTP_HOST' => self::DOMAIN],
            ['bruteforceProtectionHandler' => $handler],
        );

        $lines = is_file($this->logFile) ? array_values(array_filter(explode("\n", (string) file_get_contents($this->logFile)))) : [];
        $this->assertCount(1, $lines, 'one log entry per request');
        $this->assertSame($username, explode(',', $lines[0])[2]);
    }

    /**
     * @return array{attempt: int, block: string}
     */
    private function exhaustRateLimit(string $username): array
    {
        $address = $this->untrustedAddress();

        for ($attempt = 1; $attempt <= 8; ++$attempt) {
            $response = $this->postLostPassword($username, ['REMOTE_ADDR' => $address, 'HTTP_HOST' => self::DOMAIN]);
            $block = $this->resultBlock($response);

            if (str_contains($block, 'Too many attempts')) {
                return ['attempt' => $attempt, 'block' => $block];
            }
        }

        return ['attempt' => 0, 'block' => ''];
    }

    private function resultBlock(\Symfony\Component\HttpFoundation\Response $response): string
    {
        $matched = preg_match('~<div class="text .*?</div>~s', (string) $response->getContent(), $matches);

        return 1 === $matched ? $matches[0] : 'NO-RESULT-BLOCK-IN-RESPONSE';
    }

    private function deleteAccounts(): void
    {
        foreach ([self::KNOWN, self::INACTIVE, self::NO_EMAIL, self::NO_PASSWORD, self::MAILFAIL] as $name) {
            $existing = \Pimcore\Model\User::getByName($name);

            if ($existing instanceof \Pimcore\Model\User) {
                $existing->delete();
            }
        }
    }
}
