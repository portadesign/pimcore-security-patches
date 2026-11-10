<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-58401')]
final class AdminSessionTokenTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\RejectedSerializedPayloads;

    private const USERNAME = 'pd-sec-session-user';

    private \Pimcore\Model\User $user;

    /**
     * @var array<string, mixed>
     */
    private array $originalSystemConfiguration = [];

    protected function setUp(): void
    {
        $this->originalSystemConfiguration = \Pimcore\Config::getSystemConfiguration() ?? [];
        $this->resetCanary();
        $this->deleteUser();

        $this->user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
        ]);
    }

    protected function tearDown(): void
    {
        \Pimcore\Config::setSystemConfiguration($this->originalSystemConfiguration);
        $this->deleteUser();
        $this->resetCanary();
    }

    /**
     * @return array<string, array{class-string<\Symfony\Component\Security\Core\Authentication\Token\AbstractToken>}>
     */
    public static function legitimateTokenClassProvider(): array
    {
        return [
            'post authentication token' => [\Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken::class],
            'username password token' => [\Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken::class],
            'two factor required token' => ['Pimcore\\Bundle\\AdminBundle\\Security\\Authentication\\Token\\TwoFactorRequiredToken'],
        ];
    }

    /**
     * @param class-string<\Symfony\Component\Security\Core\Authentication\Token\AbstractToken> $tokenClass
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('legitimateTokenClassProvider')]
    public function testLegitimateSessionTokenStillAuthenticates(string $tokenClass): void
    {
        $token = new $tokenClass(new \Pimcore\Security\User\User($this->user), 'pimcore_admin', []);

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken(serialize($token)));

        $this->assertInstanceOf(\Pimcore\Model\User::class, $authenticated);
        $this->assertSame($this->user->getId(), $authenticated->getId());
    }

    public function testSessionTokenOfNonAdminUserWithWorkspacesStillAuthenticates(): void
    {
        $workspaceClasses = [
            \Pimcore\Model\User\Workspace\Asset::class,
            \Pimcore\Model\User\Workspace\Document::class,
            \Pimcore\Model\User\Workspace\DataObject::class,
        ];
        $workspaces = [];
        foreach ($workspaceClasses as $workspaceClass) {
            $workspace = new $workspaceClass();
            $workspace->setCid(1);
            $workspace->setCpath('/');
            $workspace->setList(true);
            $workspace->setView(true);
            $workspaces[] = $workspace;
        }
        $this->user->setAdmin(false);
        $this->user->setWorkspacesAsset([$workspaces[0]]);
        $this->user->setWorkspacesDocument([$workspaces[1]]);
        $this->user->setWorkspacesObject([$workspaces[2]]);
        $this->user->save();

        $user = \Pimcore\Model\User::getById($this->user->getId());
        $serialized = serialize(new \Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken(
            new \Pimcore\Security\User\User($user),
            'pimcore_admin',
            [],
        ));
        foreach ($workspaceClasses as $workspaceClass) {
            $this->assertStringContainsString('"' . $workspaceClass . '"', $serialized);
        }

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken($serialized));

        $this->assertInstanceOf(\Pimcore\Model\User::class, $authenticated);
        $this->assertSame($this->user->getId(), $authenticated->getId());
    }

    public function testBareForeignObjectInSessionIsRejected(): void
    {
        $payload = $this->serialized(fn (): mixed => $this->canary());

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken($payload));

        $this->assertNull($authenticated);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the session token.');
    }

    public function testForeignObjectNestedInTokenAttributesIsNotInstantiated(): void
    {
        $token = new \Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken(
            new \Pimcore\Security\User\User($this->user),
            'pimcore_admin',
            [],
        );
        $token->setAttribute('gadget', $this->canary());
        $payload = $this->serialized(fn (): mixed => $token);

        \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken($payload));

        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the session token.');
    }

    public function testTwoFactorTokenSurvivesSessionRoundTrip(): void
    {
        $twoFactorToken = 'Scheb\\TwoFactorBundle\\Security\\Authentication\\Token\\TwoFactorToken';
        if (!class_exists($twoFactorToken)) {
            $this->markTestSkipped('scheb/2fa-bundle is not installed on this host.');
        }

        $inner = new \Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken(new \Pimcore\Security\User\User($this->user), 'pimcore_admin', []);
        $token = new $twoFactorToken($inner, null, 'pimcore_admin', ['google']);
        $serialized = serialize($token);
        $this->assertStringContainsString('"' . $twoFactorToken . '"', $serialized);

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken($serialized));

        $this->assertInstanceOf(\Pimcore\Model\User::class, $authenticated);
        $this->assertSame($this->user->getId(), $authenticated->getId());
    }

    /**
     * @return array<string, array{\Closure(string): string}>
     */
    public static function caseVariantProvider(): array
    {
        return [
            'upper-case class name' => [static fn (string $name): string => strtoupper($name)],
            'lower-case class name' => [static fn (string $name): string => strtolower($name)],
        ];
    }

    /**
     * @param \Closure(string): string $variant
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('caseVariantProvider')]
    public function testCaseVariantOfAllowedTokenClassStillAuthenticates(\Closure $variant): void
    {
        $token = new \Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken(new \Pimcore\Security\User\User($this->user), 'pimcore_admin', []);
        $serialized = (string) preg_replace_callback(
            '/^O:(\d+):"([^"]+)"/',
            static fn (array $match): string => 'O:' . $match[1] . ':"' . $variant($match[2]) . '"',
            serialize($token),
        );

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken($serialized));

        $this->assertInstanceOf(\Pimcore\Model\User::class, $authenticated);
        $this->assertSame($this->user->getId(), $authenticated->getId());
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('rejectedSerializedPayloadProvider')]
    public function testPayloadNamingClassOutsideAllowlistIsRejectedBeforeUnserialize(string $payload): void
    {
        $result = (new \ReflectionMethod(\Pimcore\Tool\Authentication::class, 'safelyUnserialize'))->invoke(null, $payload);

        $this->assertNull($result);
        $this->assertSame(0, $this->canaryExecutions(), 'Magic methods of a foreign class ran while reading the session token.');
    }

    public function testTokenClassAddedThroughConfigurationAuthenticates(): void
    {
        $this->configureSessionTokenAllowedClasses([\Portadesign\PimcoreSecurityPatches\Tests\Support\CustomSessionToken::class]);
        $token = new \Portadesign\PimcoreSecurityPatches\Tests\Support\CustomSessionToken();
        $token->setUser(new \Pimcore\Security\User\User($this->user));

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken(serialize($token)));

        $this->assertInstanceOf(\Pimcore\Model\User::class, $authenticated);
        $this->assertSame($this->user->getId(), $authenticated->getId());
    }

    public function testTokenClassNotAddedThroughConfigurationIsRejected(): void
    {
        $token = new \Portadesign\PimcoreSecurityPatches\Tests\Support\CustomSessionToken();
        $token->setUser(new \Pimcore\Security\User\User($this->user));

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken(serialize($token)));

        $this->assertNull($authenticated);
    }

    public function testConfigurationDoesNotAllowClassesBeyondTheOnesItNames(): void
    {
        $this->configureSessionTokenAllowedClasses([\Portadesign\PimcoreSecurityPatches\Tests\Support\CustomSessionToken::class]);
        $payload = $this->serialized(fn (): mixed => $this->canary());

        $result = (new \ReflectionMethod(\Pimcore\Tool\Authentication::class, 'safelyUnserialize'))->invoke(null, $payload);

        $this->assertNull($result);
        $this->assertSame(0, $this->canaryExecutions());
    }

    public function testConfigurationKeepsBuiltInTokenClasses(): void
    {
        $this->configureSessionTokenAllowedClasses([\Portadesign\PimcoreSecurityPatches\Tests\Support\CustomSessionToken::class]);
        $token = new \Symfony\Component\Security\Http\Authenticator\Token\PostAuthenticationToken(new \Pimcore\Security\User\User($this->user), 'pimcore_admin', []);

        $authenticated = \Pimcore\Tool\Authentication::authenticateSession($this->requestWithSessionToken(serialize($token)));

        $this->assertInstanceOf(\Pimcore\Model\User::class, $authenticated);
        $this->assertSame($this->user->getId(), $authenticated->getId());
    }

    private function requestWithSessionToken(string $serializedToken): \Symfony\Component\HttpFoundation\Request
    {
        $session = new \Symfony\Component\HttpFoundation\Session\Session(
            new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage(),
        );
        $session->set('_security_pimcore_admin', $serializedToken);

        $request = new \Symfony\Component\HttpFoundation\Request();
        $request->setSession($session);
        $request->cookies->set($session->getName(), 'pd-sec-session');

        return $request;
    }

    /**
     * @param list<string> $classes
     */
    private function configureSessionTokenAllowedClasses(array $classes): void
    {
        $security = $this->originalSystemConfiguration['security'] ?? [];
        $security['session_token_allowed_classes'] = $classes;
        \Pimcore\Config::setSystemConfiguration($security, 'security');
    }

    private function deleteUser(): void
    {
        $existing = \Pimcore\Model\User::getByName(self::USERNAME);

        if ($existing instanceof \Pimcore\Model\User) {
            $existing->delete();
        }
    }

    private function canary(): object
    {
        return new \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary();
    }

    private function serialized(\Closure $factory): string
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::serialized($factory);
    }

    private function resetCanary(): void
    {
        \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::reset();
    }

    private function canaryExecutions(): int
    {
        return \Portadesign\PimcoreSecurityPatches\Tests\Support\DeserializationCanary::$executions;
    }
}
