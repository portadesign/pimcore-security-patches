<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2023-5844')]
#[\PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses]
final class PasswordReuseTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5Environment;

    private const USERNAME = 'pd-sec-reuse-user';

    private const CURRENT_PASSWORD = 'current-Passw0rd-pd';

    private const OTHER_PASSWORD = 'another-Passw0rd-pd';

    private \Pimcore\Model\User $user;

    private string $originalHash;

    protected function setUp(): void
    {
        $this->deleteUserByName(self::USERNAME);
        $this->originalHash = \Pimcore\Tool\Authentication::getPasswordHash(self::USERNAME, self::CURRENT_PASSWORD);
        $this->user = $this->createAccount(self::USERNAME, 'reuse@example.test', [], $this->originalHash);
        $this->authenticate($this->user);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->deleteUserByName(self::USERNAME);
    }

    public function testChangingToTheCurrentPasswordWithTheOldPasswordIsRejected(): void
    {
        $result = $this->updatePassword(self::CURRENT_PASSWORD, self::CURRENT_PASSWORD, self::CURRENT_PASSWORD);

        $this->assertSame(['success' => false, 'message' => 'password_cannot_be_changed'], $result);
        $this->assertSame($this->originalHash, $this->storedHash());
    }

    public function testChangingToTheCurrentPasswordWithTheResetTokenIsRejected(): void
    {
        $this->markPasswordResetInSession();

        $result = $this->updatePassword('', self::CURRENT_PASSWORD, self::CURRENT_PASSWORD);

        $this->assertSame(['success' => false, 'message' => 'password_cannot_be_changed'], $result);
        $this->assertSame($this->originalHash, $this->storedHash());
    }

    public function testControlADifferentPasswordIsStored(): void
    {
        $result = $this->updatePassword(self::CURRENT_PASSWORD, self::OTHER_PASSWORD, self::OTHER_PASSWORD);

        $this->assertSame(['success' => true], $result);
        $this->assertNotSame($this->originalHash, $this->storedHash());
        $this->assertSame($this->user->getId(), \Pimcore\Tool\Authentication::authenticatePlaintext(self::USERNAME, self::OTHER_PASSWORD)?->getId());
    }

    public function testControlAWrongOldPasswordIsRejected(): void
    {
        $result = $this->updatePassword('wrong-Passw0rd-pd', self::OTHER_PASSWORD, self::OTHER_PASSWORD);

        $this->assertSame(['success' => false, 'message' => 'password_cannot_be_changed'], $result);
        $this->assertSame($this->originalHash, $this->storedHash());
    }

    /**
     * @return array<string, mixed>
     */
    private function updatePassword(string $oldPassword, string $newPassword, string $retypePassword): array
    {
        $request = \Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/user/update-current-user',
            method: 'PUT',
            parameters: [
                'id' => $this->user->getId(),
                'data' => json_encode([
                    'old_password' => $oldPassword,
                    'new_password' => $newPassword,
                    'retype_password' => $retypePassword,
                ], JSON_THROW_ON_ERROR),
            ],
        );

        $controller = $this->adminController(\Pimcore\Bundle\AdminBundle\Controller\Admin\UserController::class);
        $response = $controller->updateCurrentUserAction($request);

        return json_decode((string) $response->getContent(), true, flags: JSON_THROW_ON_ERROR);
    }

    private function markPasswordResetInSession(): void
    {
        \Pimcore\Tool\Session::useBag(
            new \Symfony\Component\HttpFoundation\Session\Session(new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage()),
            static function (\Symfony\Component\HttpFoundation\Session\Attribute\AttributeBagInterface $adminSession): void {
                $adminSession->set('password_reset', true);
            },
        );
    }

    private function storedHash(): string
    {
        return (string) \Pimcore\Db::get()->fetchOne('SELECT password FROM users WHERE id = ?', [$this->user->getId()]);
    }
}
