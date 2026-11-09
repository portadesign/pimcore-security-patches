<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
final class TwigSandboxMutatorTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P3SandboxRendering;

    private \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage $tokenStorage;

    private \Symfony\Component\HttpFoundation\RequestStack $requestStack;

    private \Symfony\Bridge\Twig\AppVariable $app;

    protected function setUp(): void
    {
        $this->tokenStorage = new \Symfony\Component\Security\Core\Authentication\Token\Storage\TokenStorage();
        $this->requestStack = new \Symfony\Component\HttpFoundation\RequestStack();
        $this->app = new \Symfony\Bridge\Twig\AppVariable();
        $this->app->setTokenStorage($this->tokenStorage);
        $this->app->setRequestStack($this->requestStack);
    }

    protected function tearDown(): void
    {
        $this->disableSandbox();
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function elementMutatorProvider(): array
    {
        return [
            'save' => ['{{ element.save() }}', 'save'],
            'delete' => ['{{ element.delete() }}', 'delete'],
            'setter' => ["{% set changed = element.setFilename('hacked') %}", 'setFilename'],
            'bulk setter' => ["{% set changed = element.setValues({'filename': 'hacked'}) %}", 'setValues'],
            'generic setter' => ["{% set changed = element.setValue('filename', 'hacked') %}", 'setValue'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('elementMutatorProvider')]
    public function testElementMutatorIsBlockedBeforeItRuns(string $template, string $method): void
    {
        $element = $this->createMock(\Pimcore\Model\Asset\Folder::class);
        $element->expects($this->never())->method($method);

        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class, ['element' => $element]);
    }

    public function testElementMutatorLeavesElementUntouched(): void
    {
        $element = new \Pimcore\Model\Asset\Folder();
        $element->setFilename('original');

        try {
            $this->renderSandboxed("{% set changed = element.setFilename('hacked') %}", ['element' => $element]);
        } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
        }

        $this->assertSame('original', $element->getFilename());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function daoDelegatedMutatorProvider(): array
    {
        return [
            'update' => ['updateChildPaths'],
            'delete' => ['deleteAllProperties'],
            'lock' => ['lock'],
            'permission sql' => ['isInheritingPermission'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('daoDelegatedMutatorProvider')]
    public function testDaoDelegatedMutatorIsBlockedBeforeItIsForwarded(string $method): void
    {
        $element = new class () extends \Pimcore\Model\Asset\Folder {
            /**
             * @var list<string>
             */
            public array $delegated = [];

            public function __call($method, $args): mixed
            {
                $this->delegated[] = $method;

                return null;
            }
        };

        try {
            $this->renderSandboxed('{% set changed = element.' . $method . '() %}', ['element' => $element]);
        } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
        }

        $this->assertSame([], $element->delegated);
    }

    public function testHardBlockedMethodsHoldForAllowedClasses(): void
    {
        $container = \Pimcore::getContainer();
        $policy = new \Pimcore\Twig\Sandbox\SecurityPolicy(
            blockedClasses: $container->getParameter('pimcore.templating.twig.sandbox_security_policy.blocked_classes'),
            allowedClasses: [\Pimcore\Model\User::class, \Pimcore\Model\DataObject\ClassDefinition::class],
            hardBlockedMethods: $container->getParameter('pimcore.templating.twig.sandbox_security_policy.hard_blocked_methods'),
        );
        $user = new \Pimcore\Model\User();

        $policy->checkMethodAllowed($user, 'getName');
        $this->addToAssertionCount(1);

        foreach (['getPassword', 'getTwoFactorAuthentication', 'setPassword', 'save', 'delete'] as $method) {
            try {
                $policy->checkMethodAllowed($user, $method);
                $this->fail($method . ' was not rejected');
            } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
                $this->addToAssertionCount(1);
            }
        }

        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $policy->checkMethodAllowed(new \Pimcore\Model\DataObject\ClassDefinition(), 'save');
    }

    /**
     * @return array<string, array{string}>
     */
    public static function classDefinitionProvider(): array
    {
        return [
            'class description' => ["{% set changed = definition.setDescription('**// system(\$_GET[0]); /*') %}"],
            'class getter' => ['{{ definition.getFieldDefinitions() }}'],
            'brick definition' => ["{% set changed = brick.setKey('x') %}"],
            'fieldcollection definition' => ["{% set changed = collection.setKey('x') %}"],
            'custom layout' => ["{% set changed = customLayout.setDescription('x') %}"],
            'field definition' => ["{% set changed = field.setName('x') %}"],
            'layout definition' => ["{% set changed = layout.setName('x') %}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('classDefinitionProvider')]
    public function testClassDefinitionIsBlocked(string $template): void
    {
        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class, [
            'definition' => new \Pimcore\Model\DataObject\ClassDefinition(),
            'brick' => new \Pimcore\Model\DataObject\Objectbrick\Definition(),
            'collection' => new \Pimcore\Model\DataObject\Fieldcollection\Definition(),
            'customLayout' => new \Pimcore\Model\DataObject\ClassDefinition\CustomLayout(),
            'field' => new \Pimcore\Model\DataObject\ClassDefinition\Data\Input(),
            'layout' => new \Pimcore\Model\DataObject\ClassDefinition\Layout\Panel(),
        ]);
    }

    public function testClassDefinitionStaysUntouched(): void
    {
        $definition = new \Pimcore\Model\DataObject\ClassDefinition();

        try {
            $this->renderSandboxed("{% set changed = definition.setDescription('changed') %}", ['definition' => $definition]);
        } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
        }

        $this->assertNotSame('changed', $definition->getDescription());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function applicationVariableProvider(): array
    {
        return [
            'user password property' => ['{{ app.user.password }}'],
            'user password getter' => ['{{ app.user.getPassword() }}'],
            'security token user' => ['{{ app.token.getUser().getPassword() }}'],
            'session' => ["{{ app.session.get('secret') }}"],
            'request session' => ["{{ app.request.getSession().get('secret') }}"],
            'cookies' => ["{{ app.request.cookies.get('sid') }}"],
            'request headers' => ["{{ app.request.headers.get('authorization') }}"],
            'request attributes' => ["{{ app.request.attributes.get('secret') }}"],
            'request basic auth password' => ['{{ app.request.getPassword() }}'],
            'request string cast' => ['{{ app.request }}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('applicationVariableProvider')]
    public function testApplicationVariableLeakIsBlocked(string $template): void
    {
        $this->authenticate(new \Symfony\Component\Security\Core\User\InMemoryUser('sender', 'secret-hash'));
        $this->pushRequest();

        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityError::class, ['app' => $this->app]);
    }

    public function testAdminUserWrapperLeakIsBlocked(): void
    {
        $user = new \Pimcore\Model\User();
        $user->setName('sender');
        $user->setPassword('secret-hash');
        $this->authenticate(new \Pimcore\Security\User\User($user));

        $this->assertSandboxBlocks('{{ app.user.user.getPassword() }}', \Twig\Sandbox\SecurityError::class, ['app' => $this->app]);
    }

    public function testAdminUserTwoFactorSecretIsBlocked(): void
    {
        $user = new \Pimcore\Model\User();
        $user->setName('sender');
        $this->authenticate(new \Pimcore\Security\User\User($user));

        $this->assertSandboxBlocks('{{ app.user.getGoogleAuthenticatorSecret() }}', \Twig\Sandbox\SecurityError::class, ['app' => $this->app]);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function blockedFunctionProvider(): array
    {
        return [
            'dump' => ["{{ pimcore_dump('value') }}"],
            'file exists' => ["{{ pimcore_file_exists('/etc/hostname') }}"],
            'include' => ["{{ pimcore_inc('/') }}"],
            'website config' => ["{{ pimcore_website_config('key') }}"],
            'renderlet' => ["{{ pimcore_renderlet('item', {'controller': 'App\\\\Controller::action'}) }}"],
            'snippet' => ["{{ pimcore_snippet('item') }}"],
            'image version preview' => ["{{ pimcore_image_version_preview('/nonexistent') }}"],
            'head script' => ["{{ pimcore_head_script().appendFile('/x.js') }}"],
            'inline script' => ["{{ pimcore_inline_script().appendScript('x') }}"],
            'placeholder' => ["{{ pimcore_placeholder('name').set('x') }}"],
            'cache' => ["{{ pimcore_cache('key') }}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('blockedFunctionProvider')]
    public function testPimcoreFunctionIsBlocked(string $template): void
    {
        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedFunctionError::class);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function staticMethodProvider(): array
    {
        return [
            'document list' => ["{% set found = element.getList({'limit': 1}) %}"],
            'document list with listing class' => ["{% set found = element.getList({'condition': '1=1', 'class': 'Pimcore\\\\Model\\\\User\\\\Listing'}) %}"],
            'document by id' => ['{% set found = element.getById(1) %}'],
            'document by path' => ["{% set found = element.getByPath('/') %}"],
            'oracle in list' => ["{{ element in element.getList({'limit': 1}) }}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('staticMethodProvider')]
    public function testStaticMethodOnInstanceIsBlocked(string $template): void
    {
        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class, ['element' => new \Pimcore\Model\Document\Folder()]);
    }

    public function testPermissionSqlInjectionThroughDaoIsBlocked(): void
    {
        $this->assertSandboxBlocks(
            "{{ element.isInheritingPermission('view', ['1) OR (1=1']) }}",
            \Twig\Sandbox\SecurityNotAllowedMethodError::class,
            ['element' => new \Pimcore\Model\Document\Folder()],
        );
    }

    public function testUndeclaredModelMethodIsBlocked(): void
    {
        $policy = new \Pimcore\Twig\Sandbox\SecurityPolicy();
        $element = new \Pimcore\Model\Document\Folder();

        $policy->checkMethodAllowed($element, 'getKey');
        $this->addToAssertionCount(1);

        foreach (['isInheritingPermission', 'noSuchMethod', 'GETLIST'] as $method) {
            try {
                $policy->checkMethodAllowed($element, $method);
                $this->fail($method . ' was not rejected');
            } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
                $this->addToAssertionCount(1);
            }
        }
    }

    public function testControlCallMagicOnNonModelObjectStaysAllowed(): void
    {
        $policy = new \Pimcore\Twig\Sandbox\SecurityPolicy();
        $object = new class () {
            public function __call(string $method, array $args): string
            {
                return $method;
            }
        };

        $policy->checkMethodAllowed($object, 'anything');

        $this->addToAssertionCount(1);
    }

    public function testControlHarmlessRenderingStillWorks(): void
    {
        $folder = new \Pimcore\Model\Asset\Folder();
        $folder->setFilename('report');
        $this->pushRequest();

        $rendered = $this->renderSandboxed(
            '{{ element.getFilename() }}|{{ element.getType() }}|{{ app.request.getPathInfo() }}|{{ app.request.getLocale() }}',
            ['element' => $folder, 'app' => $this->app],
        );

        $this->assertSame('report|folder|/mail|en', $rendered);
    }

    private function authenticate(\Symfony\Component\Security\Core\User\UserInterface $user): void
    {
        $this->tokenStorage->setToken(new \Symfony\Component\Security\Core\Authentication\Token\UsernamePasswordToken($user, 'main', []));
    }

    private function pushRequest(): void
    {
        $request = \Symfony\Component\HttpFoundation\Request::create('/mail', 'GET', [], ['sid' => 'session-cookie'], [], ['PHP_AUTH_USER' => 'basic', 'PHP_AUTH_PW' => 'basic-secret', 'HTTP_AUTHORIZATION' => 'Bearer token']);
        $request->attributes->set('secret', 'attribute-secret');
        $request->setLocale('en');

        $session = new \Symfony\Component\HttpFoundation\Session\Session(new \Symfony\Component\HttpFoundation\Session\Storage\MockArraySessionStorage());
        $session->set('secret', 'session-secret');
        $request->setSession($session);

        $this->requestStack->push($request);
    }
}
