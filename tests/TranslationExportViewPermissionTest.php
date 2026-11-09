<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-45703')]
final class TranslationExportViewPermissionTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;

    private const USERNAME = 'pd-sec-export-user';

    private const ADMIN_USERNAME = 'pd-sec-export-admin';

    private const ROOT_KEY = 'pd-sec-export-root';

    private const VISIBLE_KEY = 'pd-sec-export-visible';

    private const HIDDEN_KEY = 'pd-sec-export-hidden';

    private const VISIBLE_TITLE = 'pd-sec-export-visible-title';

    private const HIDDEN_TITLE = 'pd-sec-export-hidden-title';

    private const WORD_EXPORT_ID = 'pdsecwordexport';

    private const XLIFF_EXPORT_ID = 'pdsecxliffexport';

    private const OUTSIDE_KEY = 'pd-sec-export-outside';

    private \Pimcore\Model\User $user;

    private \Pimcore\Model\User $admin;

    private \Pimcore\Model\Document\Page $root;

    private \Pimcore\Model\Document\Page $visible;

    private \Pimcore\Model\Document\Page $hidden;

    private \Pimcore\Model\Document\Page $outside;

    /**
     * @var array<int, \Pimcore\Model\User\Workspace\Document>
     */
    private array $workspaces = [];

    protected function setUp(): void
    {
        $this->removeFixtures();
        $this->workspaces = [];

        $this->root = $this->createPage(1, self::ROOT_KEY, self::VISIBLE_TITLE);
        $this->visible = $this->createPage($this->root->getId(), self::VISIBLE_KEY, self::VISIBLE_TITLE);
        $this->hidden = $this->createPage($this->root->getId(), self::HIDDEN_KEY, self::HIDDEN_TITLE);
        $this->outside = $this->createPage(1, self::OUTSIDE_KEY, self::HIDDEN_TITLE);

        $this->user = $this->createUser(self::USERNAME, false);
        $this->admin = $this->createUser(self::ADMIN_USERNAME, true);
        $this->grantView([$this->visible]);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);
        $this->removeFixtures();
    }

    public function testWordExportOfNonViewablePageIsDeniedAndWritesNothing(): void
    {
        try {
            $this->wordExport([$this->hidden]);
            $this->fail('Export of a page without view permission was accepted.');
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException) {
        }

        $this->assertSame('', $this->wordExportContent());
    }

    public function testWordExportMixingViewableAndNonViewablePageIsDeniedAndWritesNothing(): void
    {
        try {
            $this->wordExport([$this->visible, $this->hidden]);
            $this->fail('Export containing a page without view permission was accepted.');
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException) {
        }

        $this->assertSame('', $this->wordExportContent());
    }

    public function testWordExportSkipsUnknownElement(): void
    {
        $response = $this->wordExport([$this->visible], [['type' => 'document', 'id' => 0]]);

        $this->assertSame(200, $response->getStatusCode());
        $html = $this->wordExportContent();
        $this->assertStringContainsString('(ID: ' . $this->visible->getId() . ')', $html);
        $this->assertSame(1, substr_count($html, 'element-headline'));
    }

    public function testControlWordExportOfViewablePageContainsPage(): void
    {
        $response = $this->wordExport([$this->visible]);

        $this->assertSame(200, $response->getStatusCode());
        $html = $this->wordExportContent();
        $this->assertStringContainsString('(ID: ' . $this->visible->getId() . ')', $html);
        $this->assertStringContainsString(self::VISIBLE_TITLE, $html);
        $this->assertStringContainsString(\Portadesign\PimcoreSecurityPatches\Tests\Support\WordExportProbeController::BODY, $html);
    }

    public function testControlAdminWordExportContainsEveryPage(): void
    {
        $this->authenticate($this->admin);

        $response = $this->wordExport([$this->visible, $this->hidden]);

        $this->assertSame(200, $response->getStatusCode());
        $html = $this->wordExportContent();
        $this->assertStringContainsString('(ID: ' . $this->visible->getId() . ')', $html);
        $this->assertStringContainsString('(ID: ' . $this->hidden->getId() . ')', $html);
        $this->assertStringContainsString(self::HIDDEN_TITLE, $html);
    }

    public function testXliffExportOfNonViewablePageIsDeniedAndDoesNotLeakTitle(): void
    {
        try {
            $this->xliffExport([$this->hidden]);
            $this->fail('Export of a page without view permission was accepted.');
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException) {
        }

        $this->assertStringNotContainsString(self::HIDDEN_TITLE, $this->xliffContent());
    }

    public function testXliffExportMixingViewableAndNonViewablePageIsDeniedAndWritesNothing(): void
    {
        try {
            $this->xliffExport([$this->visible, $this->hidden]);
            $this->fail('Export containing a page without view permission was accepted.');
        } catch (\Symfony\Component\HttpKernel\Exception\AccessDeniedHttpException) {
        }

        $xliff = $this->xliffContent();
        $this->assertStringNotContainsString(self::HIDDEN_TITLE, $xliff);
        $this->assertStringNotContainsString(self::VISIBLE_TITLE, $xliff);
    }

    public function testXliffExportSkipsUnknownElement(): void
    {
        $response = $this->xliffExport([$this->visible], [['type' => 'document', 'id' => 0]]);

        $this->assertSame(200, $response->getStatusCode());
        $this->assertStringContainsString(self::VISIBLE_TITLE, $this->xliffContent());
    }

    public function testControlXliffExportOfViewablePageContainsTitle(): void
    {
        $response = $this->xliffExport([$this->visible]);

        $this->assertSame(200, $response->getStatusCode());
        $xliff = $this->xliffContent();
        $this->assertStringContainsString(self::VISIBLE_TITLE, $xliff);
        $this->assertStringNotContainsString(self::HIDDEN_TITLE, $xliff);
    }

    public function testControlAdminXliffExportContainsEveryTitle(): void
    {
        $this->authenticate($this->admin);

        $response = $this->xliffExport([$this->visible, $this->hidden]);

        $this->assertSame(200, $response->getStatusCode());
        $xliff = $this->xliffContent();
        $this->assertStringContainsString(self::VISIBLE_TITLE, $xliff);
        $this->assertStringContainsString(self::HIDDEN_TITLE, $xliff);
    }

    public function testJobsOmitNonViewableChild(): void
    {
        $this->grantView([$this->root, $this->visible]);
        $this->denyView($this->hidden);

        $ids = $this->jobElementIds([['type' => 'document', 'id' => $this->root->getId(), 'children' => true, 'relations' => false]]);

        $this->assertSame($this->sorted([$this->root->getId(), $this->visible->getId()]), $ids);
    }

    public function testJobsOmitNonViewableDependencyOfRequestedElement(): void
    {
        $this->grantView([$this->visible, $this->root]);
        $this->root->setProperty('pd-sec-export-dependency', 'document', $this->outside, false, false);
        $this->root->save();

        $ids = $this->jobElementIds([['type' => 'document', 'id' => $this->root->getId(), 'children' => false, 'relations' => true]]);

        $this->assertSame([$this->root->getId()], $ids);
    }

    public function testJobsOmitNonViewableDependencyOfChild(): void
    {
        $this->grantView([$this->root, $this->visible]);
        $this->denyView($this->hidden);
        $this->visible->setProperty('pd-sec-export-dependency', 'document', $this->outside, false, false);
        $this->visible->save();

        $ids = $this->jobElementIds([['type' => 'document', 'id' => $this->root->getId(), 'children' => true, 'relations' => true]]);

        $this->assertSame($this->sorted([$this->root->getId(), $this->visible->getId()]), $ids);
    }

    public function testJobsKeepOnlyViewableChildrenAndDependencies(): void
    {
        $this->grantView([$this->root, $this->outside]);
        $this->root->setProperty('pd-sec-export-dependency', 'document', $this->outside, false, false);
        $this->root->save();

        $ids = $this->jobElementIds([['type' => 'document', 'id' => $this->root->getId(), 'children' => true, 'relations' => true]]);

        $this->assertSame(
            $this->sorted([$this->root->getId(), $this->visible->getId(), $this->hidden->getId(), $this->outside->getId()]),
            $ids,
        );
    }

    public function testControlAdminJobsListEveryChild(): void
    {
        $this->authenticate($this->admin);

        $ids = $this->jobElementIds([['type' => 'document', 'id' => $this->root->getId(), 'children' => true, 'relations' => false]]);

        $this->assertSame(
            $this->sorted([$this->root->getId(), $this->visible->getId(), $this->hidden->getId()]),
            $ids,
        );
    }

    /**
     * @param list<\Pimcore\Model\Document\Page> $pages
     * @param list<array{type: string, id: int}> $extra
     */
    private function wordExport(array $pages, array $extra = []): \Symfony\Component\HttpFoundation\JsonResponse
    {
        return $this->controller()->wordExportAction($this->exportRequest(self::WORD_EXPORT_ID, $pages, $extra));
    }

    /**
     * @param list<\Pimcore\Model\Document\Page> $pages
     * @param list<array{type: string, id: int}> $extra
     */
    private function xliffExport(array $pages, array $extra = []): \Symfony\Component\HttpFoundation\JsonResponse
    {
        return $this->controller()->xliffExportAction(
            $this->exportRequest(self::XLIFF_EXPORT_ID, $pages, $extra),
            $this->exportService(),
        );
    }

    /**
     * @param list<\Pimcore\Model\Document\Page> $pages
     * @param list<array{type: string, id: int}> $extra
     */
    private function exportRequest(string $exportId, array $pages, array $extra): \Symfony\Component\HttpFoundation\Request
    {
        $elements = array_merge(
            array_map(static fn (\Pimcore\Model\Document\Page $page): array => ['type' => 'document', 'id' => $page->getId()], $pages),
            $extra,
        );
        $request = new \Symfony\Component\HttpFoundation\Request(request: [
            'id' => $exportId,
            'data' => json_encode($elements, JSON_THROW_ON_ERROR),
            'source' => 'en',
            'target' => 'de',
        ]);
        $request->setMethod('POST');

        return $request;
    }

    /**
     * @param list<array<string, mixed>> $elements
     *
     * @return list<int>
     */
    private function jobElementIds(array $elements): array
    {
        $request = new \Symfony\Component\HttpFoundation\Request(request: [
            'data' => json_encode($elements, JSON_THROW_ON_ERROR),
            'source' => 'en',
            'target' => 'de',
            'type' => 'xliff',
        ]);
        $request->setMethod('POST');

        $payload = json_decode((string) $this->controller()->contentExportJobsAction($request)->getContent(), true, 512, JSON_THROW_ON_ERROR);
        $ids = [];
        foreach ($payload['jobs'] as $job) {
            foreach (json_decode($job[0]['params']['data'], true, 512, JSON_THROW_ON_ERROR) as $element) {
                $ids[] = (int) $element['id'];
            }
        }

        return $this->sorted($ids);
    }

    /**
     * @param list<int> $ids
     *
     * @return list<int>
     */
    private function sorted(array $ids): array
    {
        sort($ids);

        return $ids;
    }

    private function exportService(): \Pimcore\Translation\ExportService\ExportService
    {
        $container = \Pimcore::getContainer();
        $extractors = (new \Pimcore\Translation\ExportDataExtractorService\ExportDataExtractorService())->registerDataExtractor(
            'document',
            new \Pimcore\Translation\ExportDataExtractorService\DataExtractor\DocumentDataExtractor(
                new \Pimcore\Document\Editable\EditableUsageResolver(
                    $container->get('event_dispatcher'),
                    $container->get(\Pimcore\Document\Renderer\DocumentRenderer::class),
                ),
            ),
        );

        return new \Pimcore\Translation\ExportService\ExportService(
            $extractors,
            new \Pimcore\Translation\ExportService\Exporter\Xliff12Exporter(new \Pimcore\Translation\Escaper\Xliff12Escaper()),
        );
    }

    private function controller(): \Pimcore\Bundle\AdminBundle\Controller\Admin\TranslationController
    {
        $container = \Pimcore::getContainer();

        $controller = new \Pimcore\Bundle\AdminBundle\Controller\Admin\TranslationController();
        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));

        return $controller;
    }

    private function wordExportContent(): string
    {
        $file = $this->wordExportFile();

        return is_file($file) ? (string) file_get_contents($file) : '';
    }

    private function xliffContent(): string
    {
        $file = $this->xliffFile();

        return is_file($file) ? (string) file_get_contents($file) : '';
    }

    private function wordExportFile(): string
    {
        return PIMCORE_SYSTEM_TEMP_DIRECTORY . DIRECTORY_SEPARATOR . self::WORD_EXPORT_ID . '.html';
    }

    private function xliffFile(): string
    {
        return PIMCORE_SYSTEM_TEMP_DIRECTORY . DIRECTORY_SEPARATOR . self::XLIFF_EXPORT_ID . '.xliff';
    }

    private function createPage(int $parentId, string $key, string $title): \Pimcore\Model\Document\Page
    {
        $page = new \Pimcore\Model\Document\Page();
        $page->setParentId($parentId);
        $page->setKey($key);
        $page->setTitle($title);
        $page->setController(\Portadesign\PimcoreSecurityPatches\Tests\Support\WordExportProbeController::class . '::renderAction');
        $page->setPublished(true);
        $page->save();

        return $page;
    }

    private function createUser(string $name, bool $admin): \Pimcore\Model\User
    {
        $user = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => $name,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => $admin,
        ]);
        $user->setPermissions(['documents']);
        $user->save();

        return $user;
    }

    /**
     * @param list<\Pimcore\Model\Document\Page> $pages
     */
    private function grantView(array $pages): void
    {
        foreach ($pages as $page) {
            $this->workspaces[$page->getId()] = $this->workspace($page, true);
        }

        $this->saveWorkspaces();
    }

    private function denyView(\Pimcore\Model\Document\Page $page): void
    {
        $this->workspaces[$page->getId()] = $this->workspace($page, false);
        $this->saveWorkspaces();
    }

    private function saveWorkspaces(): void
    {
        $this->user->setWorkspacesDocument(array_values($this->workspaces));
        $this->user->save();
        $this->authenticate($this->user);
    }

    private function workspace(\Pimcore\Model\Document\Page $page, bool $view): \Pimcore\Model\User\Workspace\Document
    {
        $workspace = new \Pimcore\Model\User\Workspace\Document();
        $workspace->setCid($page->getId());
        $workspace->setCpath($page->getRealFullPath());
        $workspace->setView($view);
        $workspace->setList($view);

        return $workspace;
    }

    private function removeFixtures(): void
    {
        @unlink($this->wordExportFile());
        @unlink($this->xliffFile());

        try {
            $this->deleteUserByName(self::USERNAME);
        } finally {
            try {
                $this->deleteUserByName(self::ADMIN_USERNAME);
            } finally {
                try {
                    $this->deleteDocumentByPath('/' . self::ROOT_KEY);
                } finally {
                    $this->deleteDocumentByPath('/' . self::OUTSIDE_KEY);
                }
            }
        }
    }

    private function deleteDocumentByPath(string $path): void
    {
        $page = \Pimcore\Model\Document::getByPath($path);

        if ($page instanceof \Pimcore\Model\Document) {
            $page->delete();
        }
    }
}
