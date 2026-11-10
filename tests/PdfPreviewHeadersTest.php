<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2023-46722')]
#[\PHPUnit\Framework\Attributes\Group('CVE-2023-5873')]
final class PdfPreviewHeadersTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P5Environment;

    private const USERNAME = 'pd-sec-preview-user';

    private const RESTRICTED_USERNAME = 'pd-sec-preview-restricted';

    private const FILENAME = 'pd-sec-preview.pdf';

    private const PDF = "%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert\\('pd-sec'\\)) >> >>\nendobj\n2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n";

    private int $highestMessageIdBefore = 0;

    private \Pimcore\Model\Asset\Document $asset;

    private ?\Symfony\Component\HttpFoundation\Request $previewRequest = null;

    private mixed $originalCspSettings = null;

    protected function setUp(): void
    {
        $this->highestMessageIdBefore = $this->highestMessageId();
        $this->originalCspSettings = \Pimcore\Config::getSystemConfiguration('admin_csp_header');
        $this->deleteUserByName(self::USERNAME);
        $this->deleteUserByName(self::RESTRICTED_USERNAME);
        $this->deleteAssetByPath('/' . self::FILENAME);

        $this->createAccount(self::USERNAME, null, ['assets']);
        $this->createAccount(self::RESTRICTED_USERNAME, null, []);

        $this->asset = new \Pimcore\Model\Asset\Document();
        $this->asset->setParentId(1);
        $this->asset->setFilename(self::FILENAME);
        $this->asset->setData(self::PDF);
        $this->asset->save();

        $viewer = \Pimcore\Model\User::getByName(self::USERNAME);
        $workspace = new \Pimcore\Model\User\Workspace\Asset();
        $workspace->setCid($this->asset->getId());
        $workspace->setCpath($this->asset->getRealFullPath());
        $workspace->setView(true);
        $viewer->setWorkspacesAsset([$workspace]);
        $viewer->save();
        $this->authenticate($viewer);
    }

    protected function tearDown(): void
    {
        \Pimcore\Config::setSystemConfiguration($this->originalCspSettings, 'admin_csp_header');
        $this->authenticate(null);
        $assetId = $this->asset->getId();
        $this->deleteAssetByPath('/' . self::FILENAME);
        \Pimcore\Db::get()->executeStatement('DELETE FROM versions WHERE ctype = ? AND cid = ?', ['asset', $assetId]);
        $this->deleteUserByName(self::USERNAME);
        $this->deleteUserByName(self::RESTRICTED_USERNAME);
        \Pimcore\Db::get()->executeStatement('DELETE FROM messenger_messages WHERE id > ?', [$this->highestMessageIdBefore]);
    }

    public function testPreviewResponseForbidsContentSniffing(): void
    {
        $this->assertSame('nosniff', $this->preview()->headers->get('X-Content-Type-Options'));
    }

    public function testPreviewResponseForbidsScriptExecutionThroughContentSecurityPolicy(): void
    {
        $policy = (string) $this->preview()->headers->get('Content-Security-Policy');

        $directives = [];
        foreach (array_filter(array_map('trim', explode(';', $policy))) as $directive) {
            $parts = preg_split('/\s+/', $directive);
            $directives[array_shift($parts)] = $parts;
        }

        $this->assertSame(["'none'"], $directives['script-src'] ?? null, 'script-src must be none: ' . $policy);
    }

    public function testPreviewResponseIsDisplayedInlineAsAPdf(): void
    {
        $response = $this->preview();

        $this->assertMatchesRegularExpression('/^inline; filename="?preview\.pdf"?$/', (string) $response->headers->get('Content-Disposition'));
        $this->assertSame('application/pdf', $response->headers->get('Content-Type'));
    }

    public function testPreviewPolicyIsNotReplacedByTheAdminPolicyHeader(): void
    {
        $response = $this->preview();
        $ownPolicy = (string) $response->headers->get('Content-Security-Policy');
        $this->assertNotSame('', $ownPolicy);

        $response = $this->passThroughAdminSecurityListener($this->previewRequest, $response);

        $this->assertSame($ownPolicy, $response->headers->get('Content-Security-Policy'));
    }

    public function testControlOtherAdminResponsesReceiveTheAdminPolicyHeader(): void
    {
        $request = \Symfony\Component\HttpFoundation\Request::create('/admin/settings/get-system');

        $response = $this->passThroughAdminSecurityListener($request, new \Symfony\Component\HttpFoundation\Response('{}'));

        $this->assertStringStartsWith("default-src 'self' ", (string) $response->headers->get('Content-Security-Policy'));
    }

    public function testControlPreviewStillServesTheUploadedPdf(): void
    {
        $response = $this->preview();
        ob_start();
        $response->sendContent();
        $body = (string) ob_get_clean();

        $this->assertSame('application/pdf', $response->headers->get('Content-Type'));
        $this->assertSame(200, $response->getStatusCode());
        $this->assertSame(self::PDF, $body);
    }

    public function testControlUserWithoutViewPermissionIsDenied(): void
    {
        $this->authenticate(\Pimcore\Model\User::getByName(self::RESTRICTED_USERNAME));

        $this->expectException(\Symfony\Component\Security\Core\Exception\AccessDeniedException::class);

        $this->preview();
    }

    public function testControlUnknownAssetIsNotFound(): void
    {
        $this->expectException(\Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class);

        $this->preview($this->asset->getId() + 100000);
    }

    private function preview(?int $id = null): \Symfony\Component\HttpFoundation\Response
    {
        $request = \Symfony\Component\HttpFoundation\Request::create(
            uri: '/admin/asset/get-preview-document',
            method: 'GET',
            parameters: ['id' => $id ?? $this->asset->getId()],
        );

        $this->previewRequest = $request;

        return $this->adminController(\Pimcore\Bundle\AdminBundle\Controller\Admin\Asset\AssetController::class)->getPreviewDocumentAction($request);
    }

    private function passThroughAdminSecurityListener(
        \Symfony\Component\HttpFoundation\Request $request,
        \Symfony\Component\HttpFoundation\Response $response,
    ): \Symfony\Component\HttpFoundation\Response {
        \Pimcore\Config::setSystemConfiguration(['enabled' => true, 'exclude_paths' => []], 'admin_csp_header');

        $container = \Pimcore::getContainer();
        $contextResolver = $container->get(\Pimcore\Http\Request\Resolver\PimcoreContextResolver::class);
        $contextResolver->setPimcoreContext($request, \Pimcore\Http\Request\Resolver\PimcoreContextResolver::CONTEXT_ADMIN);

        $config = new \Pimcore\Config();
        $listener = new \Pimcore\Bundle\AdminBundle\EventListener\AdminSecurityListener(
            $container->get(\Pimcore\Http\RequestHelper::class),
            new \Pimcore\Bundle\AdminBundle\Security\ContentSecurityPolicyHandler($config, []),
            $config,
        );
        $listener->setPimcoreContextResolver($contextResolver);
        $listener->onKernelResponse(new \Symfony\Component\HttpKernel\Event\ResponseEvent(
            \Pimcore::getKernel(),
            $request,
            \Symfony\Component\HttpKernel\HttpKernelInterface::MAIN_REQUEST,
            $response,
        ));

        return $response;
    }

    private function highestMessageId(): int
    {
        return (int) \Pimcore\Db::get()->fetchOne('SELECT COALESCE(MAX(id), 0) FROM messenger_messages');
    }

    private function deleteAssetByPath(string $path): void
    {
        $asset = \Pimcore\Model\Asset::getByPath($path);

        if ($asset instanceof \Pimcore\Model\Asset) {
            $asset->delete();
        }
    }
}
