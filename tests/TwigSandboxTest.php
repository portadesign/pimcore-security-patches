<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-11407')]
#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115894')]
final class TwigSandboxTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P3SandboxRendering;

    protected function tearDown(): void
    {
        $this->disableSandbox();
    }

    /**
     * @return array<string, array{string, class-string<\Twig\Sandbox\SecurityError>}>
     */
    public static function blockedTemplateProvider(): array
    {
        return [
            'user password getter' => ['{{ user.getPassword() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'user password through attribute access' => ['{{ user.password }}', \Twig\Sandbox\SecurityError::class],
            'user two factor secret' => ['{{ user.getTwoFactorAuthentication() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'user harmless getter' => ['{{ user.getName() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset binary data' => ['{{ asset.getData() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset stream' => ['{{ asset.getStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset local file' => ['{{ asset.getLocalFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'asset temporary file' => ['{{ asset.getTemporaryFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'document asset text' => ['{{ document.getText() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'image thumbnail stream' => ['{{ thumbnail.getStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'image thumbnail local file' => ['{{ thumbnail.getLocalFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'document thumbnail stream' => ['{{ documentThumbnail.getStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'document thumbnail local file' => ['{{ documentThumbnail.getLocalFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'video thumbnail stream' => ['{{ videoThumbnail.getStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'video thumbnail local file' => ['{{ videoThumbnail.getLocalFile() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'version file stream' => ['{{ version.getFileStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'version binary file stream' => ['{{ version.getBinaryFileStream() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'database connection query' => ["{{ db.fetchOne('SELECT 1') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'database connection property' => ['{{ db.params }}', \Twig\Sandbox\SecurityError::class],
            'service container' => ["{{ container.get('kernel') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'document listing condition' => ["{{ listing.setCondition('1=1') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'document listing load' => ['{{ listing.load() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'data object listing condition' => ["{{ objectListing.setCondition('1=1') }}", \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'data object dao' => ['{{ object.getDao().hasChildren() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'data object dao property' => ['{{ object.getDao().db }}', \Twig\Sandbox\SecurityError::class],
            'pdo method' => ['{{ pdo.errorCode() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'process method' => ['{{ process.getCommandLine() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'kernel method' => ['{{ kernel.getEnvironment() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'query builder method' => ['{{ queryBuilder.getSQL() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'twig environment method' => ['{{ twig.getCharset() }}', \Twig\Sandbox\SecurityNotAllowedMethodError::class],
            'pimcore user function' => ['{{ pimcore_user(1) }}', \Twig\Sandbox\SecurityNotAllowedFunctionError::class],
            'pimcore user function chained' => ['{{ pimcore_user(1).getPassword() }}', \Twig\Sandbox\SecurityNotAllowedFunctionError::class],
        ];
    }

    /**
     * @param class-string<\Twig\Sandbox\SecurityError> $expectedError
     */
    #[\PHPUnit\Framework\Attributes\DataProvider('blockedTemplateProvider')]
    public function testSandboxedTemplateIsBlocked(string $template, string $expectedError): void
    {
        $this->assertSandboxBlocks($template, $expectedError, $this->defaultContext());
    }

    public function testControlSandboxedTemplateRendersHarmlessContent(): void
    {
        $asset = new \Pimcore\Model\Asset\Folder();
        $asset->setFilename('report.txt');

        $rendered = $this->renderSandboxed(
            '{% set greeting = "Hello" %}{{ greeting }} {{ name|escape }}, {{ asset.getFilename() }}',
            ['name' => '<b>World</b>', 'asset' => $asset],
        );

        $this->assertSame('Hello &lt;b&gt;World&lt;/b&gt;, report.txt', $rendered);
    }

    public function testControlHardBlockIsLimitedToTheListedMethodsOfDocumentAssets(): void
    {
        $document = new \Pimcore\Model\Asset\Document();
        $document->setFilename('manual.pdf');

        $this->assertSame('manual.pdf', $this->renderSandboxed('{{ document.getFilename() }}', ['document' => $document]));
    }

    public function testControlRenderingWithoutSandboxStillReachesProtectedGetters(): void
    {
        $twig = $this->sandboxEngine()->getTwigEnvironment();

        $this->assertSame('hash-123', $twig->createTemplate('{{ user.getPassword() }}')->render($this->defaultContext()));
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
        $this->assertSame('admin', $this->renderWithAllowedClasses('{{ user.getName() }}', [$allowedClass]));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function userSecretGetterProvider(): array
    {
        return [
            'password' => ['getPassword'],
            'two factor secret' => ['getTwoFactorAuthentication'],
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
            'documentThumbnail' => new \Pimcore\Model\Asset\Document\ImageThumbnail(new \Pimcore\Model\Asset\Document()),
            'videoThumbnail' => new \Pimcore\Model\Asset\Video\ImageThumbnail(new \Pimcore\Model\Asset\Video()),
            'version' => new \Pimcore\Model\Version(),
            'listing' => new \Pimcore\Model\Document\Listing(),
            'objectListing' => new \Pimcore\Model\DataObject\Listing(),
            'object' => new \Pimcore\Model\DataObject\Folder(),
            'db' => \Pimcore\Db::get(),
            'pdo' => \Pimcore\Db::get()->getWrappedConnection(),
            'queryBuilder' => \Pimcore\Db::get()->createQueryBuilder(),
            'process' => new \Symfony\Component\Process\Process(['true']),
            'kernel' => \Pimcore::getKernel(),
            'twig' => $this->sandboxEngine()->getTwigEnvironment(),
            'container' => \Pimcore::getContainer(),
        ];
    }
}
