<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
final class TwigSandboxTest extends \PHPUnit\Framework\TestCase
{
    private \Pimcore\Templating\TwigDefaultDelegatingEngine $engine;

    protected function setUp(): void
    {
        $engine = \Pimcore::getContainer()->get('pimcore.templating.engine.delegating');
        \assert($engine instanceof \Pimcore\Templating\TwigDefaultDelegatingEngine);
        $this->engine = $engine;
    }

    protected function tearDown(): void
    {
        $this->engine->disableSandboxExtensionFromTwigEnvironment();
    }

    /**
     * @return array<string, array{string, class-string<\Twig\Sandbox\SecurityError>}>
     */
    public static function blockedTemplateProvider(): array
    {
        return [
            'user password getter' => ['{{ user.getPassword() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'user password through attribute access' => ['{{ user.password }}', \Twig\Sandbox\SecurityNotAllowedPropertyError::class],
            'user recovery token' => ['{{ user.getPasswordRecoveryToken() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'user two factor secret' => ['{{ user.getTwoFactorAuthentication() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'user harmless getter' => ['{{ user.getName() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset binary data' => ['{{ asset.getData() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset stream' => ['{{ asset.getStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset local file' => ['{{ asset.getLocalFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset temporary file' => ['{{ asset.getTemporaryFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'database connection query' => ["{{ db.fetchOne('SELECT 1') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'database connection property' => ['{{ db.params }}', \Twig\Sandbox\SecurityNotAllowedPropertyError::class],
            'service container' => ["{{ container.get('kernel') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'document listing condition' => ["{{ listing.setCondition('1=1') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'document listing load' => ['{{ listing.load() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'data object listing condition' => ["{{ objectListing.setCondition('1=1') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'pimcore user function' => ['{{ pimcore_user(1) }}', \Twig\Sandbox\SecurityNotAllowedFunctionError::class],
            'pimcore user function chained' => ['{{ pimcore_user(1).getPassword() }}', \Twig\Sandbox\SecurityNotAllowedFunctionError::class],
            'pdo method' => ['{{ pdo.errorCode() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'process method' => ['{{ process.getCommandLine() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'kernel method' => ['{{ kernel.getEnvironment() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'query builder method' => ['{{ queryBuilder.getSQL() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'twig environment method' => ['{{ twig.getCharset() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset document text' => ['{{ document.getText() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'image thumbnail stream' => ['{{ thumbnail.getStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'image thumbnail local file' => ['{{ thumbnail.getLocalFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'version file stream' => ['{{ version.getFileStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'version binary file stream' => ['{{ version.getBinaryFileStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
        ];
    }

    /**
     * @param class-string<\Twig\Sandbox\SecurityError> $expectedError
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('blockedTemplateProvider')]
    public function testSandboxedTemplateIsBlocked(string $template, string $expectedError): void
    {
        $this->expectException($expectedError);

        $this->render($template);
    }

    public function testSandboxedTemplateRendersHarmlessContent(): void
    {
        $asset = new \Pimcore\Model\Asset\Folder();
        $asset->setFilename('report.txt');

        $rendered = $this->render(
            '{% set greeting = "Hello" %}{{ greeting }} {{ name|escape }}, {{ asset.getFilename() }}',
            ['name' => '<b>World</b>', 'asset' => $asset],
        );

        $this->assertSame('Hello &lt;b&gt;World&lt;/b&gt;, report.txt', $rendered);
    }

    public function testHardBlockIsLimitedToTheListedMethodsOfDocumentAssets(): void
    {
        $document = new \Pimcore\Model\Asset\Document();
        $document->setFilename('manual.pdf');

        $this->assertSame('manual.pdf', $this->render('{{ document.getFilename() }}', ['document' => $document]));
    }

    /**
     * @return array<string, array{class-string}>
     */
    public static function classExemptingBlockProvider(): array
    {
        return [
            'the user class itself' => [\Pimcore\Model\User::class],
            'a parent class of the user' => [\Pimcore\Model\User\AbstractUser::class],
        ];
    }

    /**
     * @param class-string $allowedClass
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('classExemptingBlockProvider')]
    public function testAllowedClassesLiftsClassBlock(string $allowedClass): void
    {
        $rendered = $this->renderWithAllowedClasses('{{ user.getName() }}', [$allowedClass]);

        $this->assertSame('admin', $rendered);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function userSecretGetterProvider(): array
    {
        return [
            'password' => ['getPassword'],
            'password recovery token' => ['getPasswordRecoveryToken'],
            'two factor secret' => ['getTwoFactorAuthentication'],
            'api key' => ['getApiKey'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('userSecretGetterProvider')]
    public function testHardBlockedUserGetterStaysBlockedWhenUserClassIsAllowed(string $getter): void
    {
        $this->assertSame('admin', $this->renderWithAllowedClasses('{{ user.getName() }}', [\Pimcore\Model\User::class]));

        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $this->renderWithAllowedClasses('{{ user.' . $getter . '() }}', [\Pimcore\Model\User::class]);
    }

    public function testAllowedClassesDoesNotLiftBlockOfOtherClasses(): void
    {
        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $this->renderWithAllowedClasses('{{ pdo.errorCode() }}', [\Pimcore\Model\User::class]);
    }

    /**
     * @return array<string, array{string, string}>
     */
    public static function blockedPimcoreFunctionProvider(): array
    {
        return [
            'pimcore_cache' => ['pimcore_cache', "'pd-sec'"],
            'pimcore_head_link' => ['pimcore_head_link', ''],
            'pimcore_head_meta' => ['pimcore_head_meta', ''],
            'pimcore_head_script' => ['pimcore_head_script', ''],
            'pimcore_head_style' => ['pimcore_head_style', ''],
            'pimcore_head_title' => ['pimcore_head_title', ''],
            'pimcore_inline_script' => ['pimcore_inline_script', ''],
            'pimcore_placeholder' => ['pimcore_placeholder', ''],
            'pimcore_minimize_scripts' => ['pimcore_minimize_scripts', "['pd-sec.js']"],
            'pimcore_login_background_image' => ['pimcore_login_background_image', ''],
            'pimcore_language_flag' => ['pimcore_language_flag', "'en'"],
            'pimcore_video_is_available' => ['pimcore_video_is_available', ''],
            'pimcore_document_is_available' => ['pimcore_document_is_available', ''],
            'pimcore_data_object_select_options' => ['pimcore_data_object_select_options', "object, 'field'"],
            'pimcore_object_classificationstore_get_field_definition_from_json' => ['pimcore_object_classificationstore_get_field_definition_from_json', "{}, 'input'"],
            'pimcore_object_brick_definition_key' => ['pimcore_object_brick_definition_key', "'pd-sec'"],
            'pimcore_build_nav' => ['pimcore_build_nav', '{}'],
            'pimcore_render_nav' => ['pimcore_render_nav', 'nav'],
            'pimcore_nav_renderer' => ['pimcore_nav_renderer', "'menu'"],
            'pimcore_iterate_block' => ['pimcore_iterate_block', 'block'],
            'pimcore_area' => ['pimcore_area', "'pd-sec'"],
            'pimcore_areablock' => ['pimcore_areablock', "'pd-sec'"],
            'pimcore_block' => ['pimcore_block', "'pd-sec'"],
            'pimcore_checkbox' => ['pimcore_checkbox', "'pd-sec'"],
            'pimcore_date' => ['pimcore_date', "'pd-sec'"],
            'pimcore_embed' => ['pimcore_embed', "'pd-sec'"],
            'pimcore_image' => ['pimcore_image', "'pd-sec'"],
            'pimcore_input' => ['pimcore_input', "'pd-sec'"],
            'pimcore_link' => ['pimcore_link', "'pd-sec'"],
            'pimcore_multiselect' => ['pimcore_multiselect', "'pd-sec'"],
            'pimcore_numeric' => ['pimcore_numeric', "'pd-sec'"],
            'pimcore_pdf' => ['pimcore_pdf', "'pd-sec'"],
            'pimcore_relation' => ['pimcore_relation', "'pd-sec'"],
            'pimcore_relations' => ['pimcore_relations', "'pd-sec'"],
            'pimcore_scheduledblock' => ['pimcore_scheduledblock', "'pd-sec'"],
            'pimcore_select' => ['pimcore_select', "'pd-sec'"],
            'pimcore_table' => ['pimcore_table', "'pd-sec'"],
            'pimcore_textarea' => ['pimcore_textarea', "'pd-sec'"],
            'pimcore_video' => ['pimcore_video', "'pd-sec'"],
            'pimcore_wysiwyg' => ['pimcore_wysiwyg', "'pd-sec'"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('blockedPimcoreFunctionProvider')]
    public function testPimcoreFunctionOfRenderStateFilesOrEditablesIsBlocked(string $function, string $arguments): void
    {
        $storage = \Pimcore\Tool\Storage::get('admin');
        $emptyScript = 'minified_javascript_core_' . md5('') . '.js';
        $existed = $storage->fileExists($emptyScript);

        $this->expectException(\Twig\Sandbox\SecurityNotAllowedFunctionError::class);
        $this->expectExceptionMessage(sprintf('Function "%s" is not allowed', $function));

        try {
            $this->render('{{ ' . $function . '(' . $arguments . ') }}');
        } finally {
            if (!$existed && $storage->fileExists($emptyScript)) {
                $storage->delete($emptyScript);
            }
        }
    }

    public function testMinimizeScriptsCannotReadFileOutsideWebRoot(): void
    {
        $name = 'pd-sec-minimize-' . bin2hex(random_bytes(4)) . '.js';
        $file = PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . $name;
        file_put_contents($file, 'pd-sec-minimize-marker');
        $storedName = 'minified_javascript_core_' . md5("pd-sec-minimize-marker\n\n\n") . '.js';
        $storage = \Pimcore\Tool\Storage::get('admin');
        $path = str_repeat('/..', substr_count(rtrim(PIMCORE_WEB_ROOT, '/'), '/')) . $file;

        try {
            try {
                $this->render("{{ pimcore_minimize_scripts(['" . $path . "']) }}");
                $this->fail('pimcore_minimize_scripts was not rejected');
            } catch (\Twig\Sandbox\SecurityNotAllowedFunctionError) {
                $this->assertFalse($storage->fileExists($storedName));
            }
        } finally {
            @unlink($file);
            if ($storage->fileExists($storedName)) {
                $storage->delete($storedName);
            }
        }
    }

    public function testControlHarmlessPimcoreFunctionsStillRender(): void
    {
        $rendered = $this->render(
            "{{ pimcore_file_extension('report.pdf') }}|{{ pimcore_object(0) is null }}|{{ pimcore_asset(0) is null }}|{{ pimcore_document(0) is null }}|{{ pimcore_site(0) is null }}|{{ path('pimcore_admin_login') }}",
        );

        $this->assertSame('pdf|1|1|1|1|' . \Pimcore::getContainer()->get('router')->generate('pimcore_admin_login'), $rendered);
    }

    public function testContentSecurityPolicyHandlerIsBlocked(): void
    {
        $this->expectException(\Twig\Sandbox\SecurityNotAllowedMethodError::class);

        $this->render('{{ pimcore_csp.getNonceHtmlAttribute() }}');
    }

    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    #[\PHPUnit\Framework\Attributes\PreserveGlobalState(false)]
    public function testMailRenderingDoesNotExposeTheAdminCsrfToken(): void
    {
        $twig = $this->engine->getTwigEnvironment();
        $twig->addGlobal('csrfToken', 'pd-sec-csrf-token');

        try {
            $mail = new \Pimcore\Mail();
            $mail->subject('subject-{{ csrfToken }}');
            $mail->html('<p>{{ csrfToken }}</p>');

            $this->assertSame('subject-', $mail->getSubjectRendered());
            $body = $mail->getBodyHtmlRendered();
            $this->assertStringContainsString('<p></p>', $body);
            $this->assertStringNotContainsString('pd-sec-csrf-token', $body);
        } finally {
            $twig->addGlobal('csrfToken', null);
        }
    }

    #[\PHPUnit\Framework\Attributes\RunInSeparateProcess]
    #[\PHPUnit\Framework\Attributes\PreserveGlobalState(false)]
    public function testTextLayoutRenderingDoesNotExposeTheAdminCsrfToken(): void
    {
        $twig = $this->engine->getTwigEnvironment();
        $twig->addGlobal('csrfToken', 'pd-sec-csrf-token');

        try {
            $layout = new \Pimcore\Model\DataObject\ClassDefinition\Layout\Text();
            $layout->setHtml('<p>{{ csrfToken }}</p>');
            $layout->enrichLayoutDefinition(null);

            $this->assertSame('<p></p>', $layout->getHtml());
        } finally {
            $twig->addGlobal('csrfToken', null);
        }
    }

    public function testMailSubjectRenderingBlocksPasswordLeak(): void
    {
        $user = new \Pimcore\Model\User();
        $user->setPassword('hash-123');

        $mail = new \Pimcore\Mail();
        $mail->setParam('user', $user);
        $mail->subject('Reset {{ user.getPassword() }}');

        try {
            $rendered = $mail->getSubjectRendered();
        } catch (\TypeError $e) {
            // 11.5.14.1 names the template pimcore_email_subject but still cuts the message at ' in "__string', so substr() gets false
            $this->assertStringContainsString('substr(): Argument #3', $e->getMessage());

            return;
        } catch (\Exception $e) {
            $this->assertMatchesRegularExpression('/^Failed rendering the subject: Calling method "getPassword" on "Pimcore\\\\Model\\\\User" is not allowed in templates\./', $e->getMessage());

            return;
        }

        $this->fail('Subject rendered without a sandbox error: ' . $rendered);
    }

    /**
     * @param list<class-string> $allowedClasses
     */
    private function renderWithAllowedClasses(string $template, array $allowedClasses): string
    {
        $container = \Pimcore::getContainer();
        $parameter = static fn (string $name): array => $container->getParameter('pimcore.templating.twig.sandbox_security_policy.' . $name);

        $policy = new \Pimcore\Twig\Sandbox\SecurityPolicy(
            allowedTags: $parameter('tags'),
            allowedFilters: $parameter('filters'),
            allowedFunctions: $parameter('functions'),
            blockedClasses: $parameter('blocked_classes'),
            allowedClasses: $allowedClasses,
            blockedFunctions: $parameter('blocked_functions'),
            hardBlockedMethods: $parameter('hard_blocked_methods'),
        );
        $twig = new \Twig\Environment(new \Twig\Loader\ArrayLoader());
        $twig->addExtension(new \Twig\Extension\SandboxExtension($policy, true));

        return $twig->createTemplate($template)->render($this->defaultContext());
    }

    /**
     * @return array<string, mixed>
     */
    private function defaultContext(): array
    {
        $user = new \Pimcore\Model\User();
        $user->setName('admin');
        $user->setPassword('hash-123');

        return [
            'user' => $user,
            'asset' => new \Pimcore\Model\Asset\Text(),
            'document' => new \Pimcore\Model\Asset\Document(),
            'thumbnail' => new \Pimcore\Model\Asset\Image\Thumbnail(new \Pimcore\Model\Asset\Image()),
            'version' => new \Pimcore\Model\Version(),
            'listing' => new \Pimcore\Model\Document\Listing(),
            'objectListing' => new \Pimcore\Model\DataObject\Listing(),
            'db' => \Pimcore\Db::get(),
            'pdo' => \Pimcore\Db::get()->getNativeConnection(),
            'queryBuilder' => \Pimcore\Db::get()->createQueryBuilder(),
            'process' => new \Symfony\Component\Process\Process(['true']),
            'kernel' => \Pimcore::getKernel(),
            'twig' => $this->engine->getTwigEnvironment(),
            'container' => \Pimcore::getContainer(),
        ];
    }

    /**
     * @param array<string, mixed> $context
     */
    private function render(string $template, array $context = []): string
    {
        $defaults = $this->defaultContext();

        $twig = $this->engine->getTwigEnvironment(true);

        return $twig->createTemplate($template)->render(array_merge($defaults, $context));
    }
}
