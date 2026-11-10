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

    protected function setUp(): void
    {
        $this->highestMessageIdBefore = $this->highestMessageId();
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
        $this->authenticate(null);
        $this->deleteAssetByPath('/' . self::FILENAME);
        $this->deleteUserByName(self::USERNAME);
        $this->deleteUserByName(self::RESTRICTED_USERNAME);
        \Pimcore\Db::get()->executeStatement('DELETE FROM messenger_messages WHERE id > ?', [$this->highestMessageIdBefore]);
    }

    public function testPreviewResponseForbidsContentSniffing(): void
    {
        $this->assertSame('nosniff', $this->preview()->headers->get('X-Content-Type-Options'));
    }

    public function testPreviewResponseCarriesARestrictiveContentSecurityPolicy(): void
    {
        $policy = (string) $this->preview()->headers->get('Content-Security-Policy');

        $directives = [];
        foreach (array_filter(array_map('trim', explode(';', $policy))) as $directive) {
            $parts = preg_split('/\s+/', $directive);
            $directives[array_shift($parts)] = $parts;
        }

        $this->assertSame(["'none'"], $directives['default-src'] ?? null, 'default-src must be none: ' . $policy);
        $this->assertArrayNotHasKey('script-src', $directives, 'no script source may be allowed: ' . $policy);
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

        return $this->adminController(\Pimcore\Bundle\AdminBundle\Controller\Admin\Asset\AssetController::class)->getPreviewDocumentAction($request);
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
