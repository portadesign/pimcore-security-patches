<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
final class TwigSandboxPolicyAuditTest extends \PHPUnit\Framework\TestCase
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
        $this->app->setEnvironment('test');
        $this->app->setDebug(false);
    }

    protected function tearDown(): void
    {
        $this->disableSandbox();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function auditedFunctionProvider(): array
    {
        $names = [
            'language_flag', 'video_is_available', 'document_is_available', 'data_object_select_options',
            'object_classificationstore_get_field_definition_from_json', 'object_brick_definition_key',
            'build_nav', 'render_nav', 'nav_renderer', 'iterate_block',
            'head_link', 'head_meta', 'head_style', 'head_title',
            'area', 'areablock', 'block', 'checkbox', 'date', 'embed', 'image', 'input', 'link', 'multiselect',
            'numeric', 'pdf', 'relation', 'relations', 'scheduledblock', 'select', 'table', 'textarea', 'video', 'wysiwyg',
        ];

        $rows = [];
        foreach ($names as $name) {
            $rows[$name] = ['pimcore_' . $name . "('x', 'x')"];
        }

        return $rows;
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('auditedFunctionProvider')]
    public function testAuditedPimcoreFunctionIsBlocked(string $call): void
    {
        $this->assertSandboxBlocks('{% set result = ' . $call . ' %}', \Twig\Sandbox\SecurityNotAllowedFunctionError::class);
    }

    public function testMinimizeScriptsCannotReadFilesOutsideTheWebRoot(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'pd-sec-');
        $this->assertIsString($file);
        file_put_contents($file, 'sentinel');
        $storage = \Pimcore\Tool\Storage::get('admin');
        $before = $this->storedPaths($storage);

        try {
            $this->assertSandboxBlocks(
                '{{ pimcore_minimize_scripts([path]) }}',
                \Twig\Sandbox\SecurityNotAllowedFunctionError::class,
                ['path' => '/' . str_repeat('../', 12) . ltrim($file, '/')],
            );
            $written = array_values(array_diff($this->storedPaths($storage), $before));
        } finally {
            @unlink($file);
            foreach (array_diff($this->storedPaths($storage), $before) as $path) {
                $storage->delete($path);
            }
        }

        $this->assertSame([], $written, 'file contents were written to the admin storage');
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function permittedFunctionProvider(): array
    {
        return [
            'pimcore_object' => ["{{ pimcore_object(999999999) is null ? 'missing' : 'found' }}", 'missing'],
            'pimcore_asset' => ["{{ pimcore_asset(999999999) is null ? 'missing' : 'found' }}", 'missing'],
            'pimcore_document' => ["{{ pimcore_document(999999999) is null ? 'missing' : 'found' }}", 'missing'],
            'pimcore_site' => ["{{ pimcore_site(999999999) is null ? 'missing' : 'found' }}", 'missing'],
            'pimcore_file_extension' => ["{{ pimcore_file_extension('report.txt') }}", 'txt'],
            'pimcore_supported_locales' => ["{% set locales = pimcore_supported_locales() %}{{ locales.en ? 'en' : 'none' }}", 'en'],
            'pimcore_url' => ["{{ pimcore_url({}, 'pimcore_admin_login') }}", '/admin/login'],
            'path' => ["{{ path('pimcore_admin_login') }}", '/admin/login'],
            'asset' => ["{{ asset('logo.png') }}", '/logo.png'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('permittedFunctionProvider')]
    public function testControlPermittedFunctionStillRenders(string $template, string $expected): void
    {
        $this->assertSame($expected, $this->renderSandboxed($template));
    }

    public function testControlImageThumbnailFunctionStillRenders(): void
    {
        $image = new \Pimcore\Model\Asset\Image();
        $image->setFilename('pd-sec.png');
        $image->setPath('/');

        $rendered = $this->renderSandboxed("{{ pimcore_image_thumbnail(image, 'pimcore-system-treepreview') }}", ['image' => $image]);

        $this->assertSame(
            (string) $image->getThumbnail('pimcore-system-treepreview'),
            $rendered,
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function requestMutatorProvider(): array
    {
        $readers = [
            'toArray', 'getContent', 'get', 'getQueryString', 'getRequestUri', 'getUri', 'getClientIp', 'getClientIps',
            'getUser', 'getPassword', 'getUserInfo', 'getSession', 'hasSession', 'hasPreviousSession', 'getETags',
            'getPreferredLanguage', 'getLanguages', 'getCharsets', 'getEncodings', 'getAcceptableContentTypes',
            'duplicate', 'overrideGlobals', 'enableHttpMethodParameterOverride',
        ];

        $rows = [];
        foreach ($readers as $method) {
            $rows[$method] = ['{% set result = app.request.' . $method . "('secret') %}"];
        }
        $rows['initialize'] = ["{% set result = app.request.initialize({'a': 'b'}) %}"];
        $rows['setLocale'] = ["{% set result = app.request.setLocale('de') %}"];
        $rows['setDefaultLocale'] = ["{% set result = app.request.setDefaultLocale('de') %}"];
        $rows['setRequestFormat'] = ["{% set result = app.request.setRequestFormat('json') %}"];
        $rows['setMethod'] = ["{% set result = app.request.setMethod('DELETE') %}"];
        $rows['setSession'] = ['{% set result = app.request.setSession(null) %}'];

        return $rows;
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('requestMutatorProvider')]
    public function testRequestMutatorAndInputReaderAreBlocked(string $template): void
    {
        $this->pushRequest();

        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class, ['app' => $this->app]);
    }

    public function testRequestStaysUntouchedByTemplates(): void
    {
        $this->pushRequest();

        foreach (["{% set changed = app.request.setLocale('de') %}", "{% set changed = app.request.setMethod('DELETE') %}"] as $template) {
            try {
                $this->renderSandboxed($template, ['app' => $this->app]);
            } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
            }
        }

        $request = $this->requestStack->getCurrentRequest();
        $this->assertSame(['en', 'POST'], [$request?->getLocale(), $request?->getMethod()]);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function requestReaderControlProvider(): array
    {
        return [
            'getLocale' => ['{{ app.request.getLocale() }}', 'en'],
            'getPathInfo' => ['{{ app.request.getPathInfo() }}', '/mail'],
            'getBasePath' => ["[{{ app.request.getBasePath() }}]", '[]'],
            'getBaseUrl' => ["[{{ app.request.getBaseUrl() }}]", '[]'],
            'getScheme' => ['{{ app.request.getScheme() }}', 'http'],
            'getPort' => ['{{ app.request.getPort() }}', '80'],
            'getHost' => ['{{ app.request.getHost() }}', 'localhost'],
            'getHttpHost' => ['{{ app.request.getHttpHost() }}', 'localhost'],
            'getSchemeAndHttpHost' => ['{{ app.request.getSchemeAndHttpHost() }}', 'http://localhost'],
            'getMethod' => ['{{ app.request.getMethod() }}', 'POST'],
            'getRealMethod' => ['{{ app.request.getRealMethod() }}', 'POST'],
            'isMethod' => ["{{ app.request.isMethod('POST') ? 'y' : 'n' }}", 'y'],
            'isSecure' => ["{{ app.request.isSecure() ? 'y' : 'n' }}", 'n'],
            'isXmlHttpRequest' => ["{{ app.request.isXmlHttpRequest() ? 'y' : 'n' }}", 'n'],
            'getRequestFormat' => ['{{ app.request.getRequestFormat() }}', 'html'],
            'getContentType' => ['{{ app.request.getContentType() }}', 'json'],
            'getProtocolVersion' => ['{{ app.request.getProtocolVersion() }}', 'HTTP/1.1'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('requestReaderControlProvider')]
    public function testControlRequestReaderStillRenders(string $template, string $expected): void
    {
        $this->pushRequest();

        $this->assertSame($expected, $this->renderSandboxed($template, ['app' => $this->app]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function appVariableProvider(): array
    {
        return [
            'flashes' => ['{{ app.flashes }}'],
            'flashes reader' => ["{{ app.flashes('notice') }}"],
            'set environment' => ["{% set changed = app.setEnvironment('prod') %}"],
            'set debug' => ['{% set changed = app.setDebug(true) %}'],
            'set token storage' => ['{% set changed = app.setTokenStorage(null) %}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('appVariableProvider')]
    public function testAppVariableStateAccessIsBlocked(string $template): void
    {
        $this->pushRequest();

        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityError::class, ['app' => $this->app]);
    }

    public function testAppVariableStaysUntouchedByTemplates(): void
    {
        try {
            $this->renderSandboxed("{% set changed = app.setEnvironment('prod') %}", ['app' => $this->app]);
        } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
        }

        $this->assertSame('test', $this->app->getEnvironment());
    }

    public function testControlAppEnvironmentStillRenders(): void
    {
        $this->assertSame('test', $this->renderSandboxed('{{ app.environment }}', ['app' => $this->app]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function workflowReaderProvider(): array
    {
        return [
            'apply' => ["{% set result = workflow.apply(subject, 'publish') %}"],
            'marking store' => ['{% set result = workflow.getMarkingStore() %}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('workflowReaderProvider')]
    public function testWorkflowTransitionAndMarkingStoreAccessIsBlocked(string $template): void
    {
        $workflow = $this->createMock(\Symfony\Component\Workflow\WorkflowInterface::class);
        foreach (['apply', 'getMarkingStore'] as $method) {
            $workflow->expects($this->never())->method($method);
        }

        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class, ['workflow' => $workflow, 'subject' => new \stdClass()]);
    }

    public function testRegistryCannotReceiveWorkflowsFromATemplate(): void
    {
        $workflow = $this->createStub(\Symfony\Component\Workflow\WorkflowInterface::class);
        $workflow->method('getName')->willReturn('pd-sec-workflow');
        $registry = new \Symfony\Component\Workflow\Registry();
        $strategy = new \Symfony\Component\Workflow\SupportStrategy\InstanceOfSupportStrategy(\stdClass::class);

        $this->assertSandboxBlocks(
            '{% set result = registry.addWorkflow(workflow, strategy) %}',
            \Twig\Sandbox\SecurityNotAllowedMethodError::class,
            ['registry' => $registry, 'workflow' => $workflow, 'strategy' => $strategy],
        );
        $this->assertSame([], $registry->all(new \stdClass()));
    }

    public function testMarkingStoreCannotBeWrittenFromATemplate(): void
    {
        $store = $this->createMock(\Symfony\Component\Workflow\MarkingStore\MarkingStoreInterface::class);
        $store->expects($this->never())->method('setMarking');

        $this->assertSandboxBlocks(
            '{% set result = store.setMarking(subject, marking) %}',
            \Twig\Sandbox\SecurityNotAllowedMethodError::class,
            ['store' => $store, 'subject' => new \stdClass(), 'marking' => new \Symfony\Component\Workflow\Marking()],
        );
    }

    public function testControlWorkflowReadersStillRender(): void
    {
        $definition = new \Symfony\Component\Workflow\Definition(['draft', 'published'], [], 'draft');
        $workflow = $this->createStub(\Symfony\Component\Workflow\WorkflowInterface::class);
        $workflow->method('getName')->willReturn('pd-sec-workflow');
        $workflow->method('getDefinition')->willReturn($definition);
        $workflow->method('can')->willReturn(true);

        $this->assertSame(
            'pd-sec-workflow|draft|yes',
            $this->renderSandboxed(
                "{{ workflow.getName() }}|{{ workflow.getDefinition().getInitialPlaces()[0] }}|{{ workflow.can(subject, 'publish') ? 'yes' : 'no' }}",
                ['workflow' => $workflow, 'subject' => new \stdClass()],
            ),
        );
    }

    public function testControlWorkflowMarkingReadStillRenders(): void
    {
        $workflow = $this->createStub(\Symfony\Component\Workflow\WorkflowInterface::class);
        $workflow->method('getMarking')->willReturn(new \Symfony\Component\Workflow\Marking(['draft' => 1]));

        $this->assertSame(
            'y|n',
            $this->renderSandboxed(
                "{% set marking = workflow.getMarking(subject) %}{{ marking.has('draft') ? 'y' : 'n' }}|{{ marking.has('published') ? 'y' : 'n' }}",
                ['workflow' => $workflow, 'subject' => new \stdClass()],
            ),
        );
    }

    /**
     * @return array<string, array{string}>
     */
    public static function markingMutatorProvider(): array
    {
        return [
            'mark' => ["{% set result = marking.mark('published') %}"],
            'unmark' => ["{% set result = marking.unmark('draft') %}"],
            'set context' => ["{% set result = marking.setContext({'a': 'b'}) %}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('markingMutatorProvider')]
    public function testMarkingMutatorIsBlocked(string $template): void
    {
        $marking = new \Symfony\Component\Workflow\Marking(['draft' => 1]);

        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class, ['marking' => $marking]);
        $this->assertSame([['draft' => 1], null], [$marking->getPlaces(), $marking->getContext()]);
    }

    public function testControlMarkingReadersStillRender(): void
    {
        $marking = new \Symfony\Component\Workflow\Marking(['draft' => 1]);

        $this->assertSame("y|1", $this->renderSandboxed("{{ marking.has('draft') ? 'y' : 'n' }}|{{ marking.getPlaces()['draft'] }}", ['marking' => $marking]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function catalogueMutatorProvider(): array
    {
        return [
            'set' => ["{% set result = catalogue.set('greeting', 'injected') %}"],
            'add' => ["{% set result = catalogue.add({'greeting': 'injected'}) %}"],
            'replace' => ["{% set result = catalogue.replace({'greeting': 'injected'}) %}"],
            'add catalogue' => ['{% set result = catalogue.addCatalogue(other) %}'],
            'add fallback catalogue' => ['{% set result = catalogue.addFallbackCatalogue(other) %}'],
            'set metadata' => ["{% set result = catalogue.setMetadata('key', 'value') %}"],
            'delete metadata' => ["{% set result = catalogue.deleteMetadata('key') %}"],
            'add resource' => ['{% set result = catalogue.addResource(resource) %}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('catalogueMutatorProvider')]
    public function testCatalogueMutatorIsBlocked(string $template): void
    {
        $translator = $this->translatorWithGreeting();
        $catalogue = $translator->getCatalogue('en');

        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class, [
            'catalogue' => $catalogue,
            'other' => new \Symfony\Component\Translation\MessageCatalogue('en', ['messages' => ['other' => 'Other']]),
            'resource' => new \Symfony\Component\Config\Resource\FileResource(__FILE__),
        ]);
        $this->assertSame(
            ['all' => ['messages' => ['greeting' => 'Hello']], 'metadata' => null, 'resources' => 0, 'fallback' => null],
            [
                'all' => $catalogue->all(),
                'metadata' => $catalogue->getMetadata(),
                'resources' => count($catalogue->getResources()),
                'fallback' => $catalogue->getFallbackCatalogue(),
            ],
        );
    }

    public function testControlCatalogueReadersStillRender(): void
    {
        $translator = $this->translatorWithGreeting();

        $this->assertSame(
            'Hello|y|n|Hello|en',
            $this->renderSandboxed(
                "{% set catalogue = translator.getCatalogue() %}{{ catalogue.get('greeting') }}|{{ catalogue.has('greeting') ? 'y' : 'n' }}|{{ catalogue.has('missing') ? 'y' : 'n' }}|{{ catalogue.all('messages').greeting }}|{{ catalogue.getLocale() }}",
                ['translator' => $translator],
            ),
        );
    }

    public function testTranslatorLocaleCannotBeChangedFromATemplate(): void
    {
        $translator = \Pimcore::getContainer()->get('translator');
        $locale = $translator->getLocale();

        $this->assertSandboxBlocks("{% set changed = translator.setLocale('cs') %}", \Twig\Sandbox\SecurityNotAllowedMethodError::class, ['translator' => $translator]);
        $this->assertSame($locale, $translator->getLocale());
    }

    public function testTranslatorResourcesCannotBeAddedFromATemplate(): void
    {
        $translator = new \Symfony\Component\Translation\Translator('en');
        $translator->addLoader('array', new \Symfony\Component\Translation\Loader\ArrayLoader());

        $this->assertSandboxBlocks(
            "{% set changed = translator.addResource('array', {'greeting': 'injected'}, 'en') %}",
            \Twig\Sandbox\SecurityNotAllowedMethodError::class,
            ['translator' => $translator],
        );
        $this->assertSame('greeting', $translator->trans('greeting'));
    }

    public function testControlTranslatorStillTranslates(): void
    {
        $translator = new \Symfony\Component\Translation\Translator('en');
        $translator->addLoader('array', new \Symfony\Component\Translation\Loader\ArrayLoader());
        $translator->addResource('array', ['greeting' => 'Hello'], 'en');

        $this->assertSame(
            'Hello|unknown',
            $this->renderSandboxed("{{ translator.trans('greeting') }}|{{ translator.trans('unknown') }}", ['translator' => $translator]),
        );
        $this->assertSame('en', $translator->getLocale());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function deviceDetectorMutatorProvider(): array
    {
        return [
            'device type' => ["{% set changed = pimcore_device().setDeviceType('phone') %}"],
            'was used' => ['{% set changed = pimcore_device().setWasUsed(true) %}'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('deviceDetectorMutatorProvider')]
    public function testDeviceDetectorStateCannotBeChangedFromATemplate(string $template): void
    {
        $this->resetDeviceDetector();
        $device = \Pimcore\Tool\DeviceDetector::getInstance();

        try {
            $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class);
            $wasUsed = $device->wasUsed();
            $this->assertSame([false, 'desktop'], [$wasUsed, $device->getDevice()]);
        } finally {
            $this->resetDeviceDetector();
        }
    }

    public function testControlDeviceDetectorReadersStillRender(): void
    {
        $this->resetDeviceDetector();

        try {
            $this->assertSame('desktop|yes', $this->renderSandboxed("{{ pimcore_device().getDevice() }}|{{ pimcore_device().isDesktop() ? 'yes' : 'no' }}"));
        } finally {
            $this->resetDeviceDetector();
        }
    }

    /**
     * @return array<string, array{string}>
     */
    public static function contentSecurityPolicyHandlerProvider(): array
    {
        return [
            'header' => ['{{ pimcore_csp.getCspHeader() }}'],
            'nonce attribute' => ['{{ pimcore_csp.getNonceHtmlAttribute() }}'],
            'header option' => ["{% set changed = pimcore_csp.setCspHeader('script-src', '*') %}"],
            'allowed urls' => ["{% set changed = pimcore_csp.addAllowedUrls('script-src', ['https://evil.example']) %}"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('contentSecurityPolicyHandlerProvider')]
    public function testContentSecurityPolicyHandlerIsBlocked(string $template): void
    {
        $this->assertSandboxBlocks($template, \Twig\Sandbox\SecurityNotAllowedMethodError::class);
    }

    public function testContentSecurityPolicyHandlerStaysUntouchedByTemplates(): void
    {
        $handler = \Pimcore::getContainer()->get(\Pimcore\Bundle\AdminBundle\Security\ContentSecurityPolicyHandler::class);
        $header = $handler->getCspHeader();

        try {
            $this->renderSandboxed("{% set changed = pimcore_csp.setCspHeader('script-src', '*') %}{% set changed = pimcore_csp.addAllowedUrls('script-src', ['https://evil.example']) %}");
        } catch (\Twig\Sandbox\SecurityNotAllowedMethodError) {
        }

        $this->assertSame($header, $handler->getCspHeader());
    }

    private function resetDeviceDetector(): void
    {
        (new \ReflectionProperty(\Pimcore\Tool\DeviceDetector::class, 'instance'))->setValue(null, null);
    }

    private function translatorWithGreeting(): \Symfony\Component\Translation\Translator
    {
        $translator = new \Symfony\Component\Translation\Translator('en');
        $translator->addLoader('array', new \Symfony\Component\Translation\Loader\ArrayLoader());
        $translator->addResource('array', ['greeting' => 'Hello'], 'en');

        return $translator;
    }

    private function pushRequest(): void
    {
        $request = \Symfony\Component\HttpFoundation\Request::create(
            'http://localhost/mail?token=query-secret',
            'POST',
            [],
            ['sid' => 'cookie-secret'],
            [],
            ['HTTP_AUTHORIZATION' => 'Bearer header-secret', 'CONTENT_TYPE' => 'application/json', 'PHP_AUTH_USER' => 'basic', 'PHP_AUTH_PW' => 'basic-secret'],
            '{"secret":"body-secret"}',
        );
        $request->attributes->set('secret', 'attribute-secret');
        $request->setLocale('en');
        $this->requestStack->push($request);
    }

    /**
     * @return list<string>
     */
    private function storedPaths(\League\Flysystem\FilesystemOperator $storage): array
    {
        return array_map(
            static fn (\League\Flysystem\StorageAttributes $item): string => $item->path(),
            $storage->listContents('/', false)->toArray(),
        );
    }
}
