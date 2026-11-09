<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-004')]
final class ExportPathDisclosureTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\AdminUserSession;
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\P4ReportScratchTable;

    private const ADMIN_USERNAME = 'pd-sec-pathdisclosure-admin';

    private const REPORT_NAME = 'pd-sec-pathdisclosure-report';

    private const PAGE_KEY = 'pd-sec-pathdisclosure-page';

    private const KNOWN_ID = 'pdsecpathdisclosureknown';

    private const UNKNOWN_ID = 'pdsecpathdisclosureunknown';

    private const TRAVERSAL_ID = '../pd-sec-pathdisclosure-traversal';

    private \Pimcore\Model\User $admin;

    private \Pimcore\Model\Document\Page $page;

    /**
     * @var list<string>
     */
    private array $exportFiles = [];

    public static function setUpBeforeClass(): void
    {
        require_once __DIR__ . '/Support/P4CsvFormulaFormatterShim.php';
    }

    protected function setUp(): void
    {
        $this->removeFixtures();
        $this->createReportScratchTable();

        $this->page = new \Pimcore\Model\Document\Page();
        $this->page->setParentId(1);
        $this->page->setKey(self::PAGE_KEY);
        $this->page->setTitle('pd-sec-pathdisclosure-title');
        $this->page->setController(\Portadesign\PimcoreSecurityPatches\Tests\Support\WordExportProbeController::class . '::renderAction');
        $this->page->setPublished(true);
        $this->page->save();

        $this->admin = \Pimcore\Model\User::create([
            'parentId' => 0,
            'name' => self::ADMIN_USERNAME,
            'password' => password_hash(bin2hex(random_bytes(16)), PASSWORD_DEFAULT),
            'active' => true,
            'admin' => true,
        ]);
        $this->authenticate($this->admin);
    }

    protected function tearDown(): void
    {
        $this->authenticate(null);

        try {
            $this->removeFixtures();
        } finally {
            $this->dropReportScratchTable();
        }
    }

    public function testWordExportDownloadOfUnknownExportDoesNotRevealFilesystemPath(): void
    {
        $this->assertNotFoundWithoutPath(fn () => $this->translationController()->wordExportDownloadAction($this->request(['id' => self::UNKNOWN_ID])));
    }

    public function testXliffExportWithTraversalIdIsRejectedAndWritesOutsideNothing(): void
    {
        $thrown = null;

        try {
            $this->translationController()->xliffExportAction(
                $this->request(['id' => self::TRAVERSAL_ID, 'data' => json_encode([['type' => 'document', 'id' => $this->page->getId()]], JSON_THROW_ON_ERROR), 'source' => 'en', 'target' => 'de']),
                $this->exportService(),
            );
        } catch (\Symfony\Component\HttpKernel\Exception\BadRequestHttpException $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(\Symfony\Component\HttpKernel\Exception\BadRequestHttpException::class, $thrown, 'Export id with path traversal was accepted; file written: ' . (is_file($this->traversalFile()) ? 'yes' : 'no'));
        $this->assertFileDoesNotExist($this->traversalFile());
    }

    public function testXliffDownloadWithTraversalIdIsRejected(): void
    {
        $thrown = null;

        try {
            $this->translationController()->xliffExportDownloadAction(
                $this->request(['id' => self::TRAVERSAL_ID]),
                $this->exportService()->getTranslationExporter(),
                $this->exportService(),
            );
        } catch (\Symfony\Component\HttpKernel\Exception\BadRequestHttpException $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(\Symfony\Component\HttpKernel\Exception\BadRequestHttpException::class, $thrown, 'Download id with path traversal was accepted; file created: ' . (is_file($this->traversalFile()) ? 'yes' : 'no'));
        $this->assertFileDoesNotExist($this->traversalFile());
    }

    public function testXliffDownloadOfUnknownExportIsNotFoundAndCreatesNoFile(): void
    {
        $this->assertNotFoundWithoutPath(fn () => $this->translationController()->xliffExportDownloadAction(
            $this->request(['id' => self::UNKNOWN_ID]),
            $this->exportService()->getTranslationExporter(),
            $this->exportService(),
        ));
        $this->assertFileDoesNotExist($this->xliffFile(self::UNKNOWN_ID));
    }

    public function testCsvDownloadOfMissingExportDoesNotRevealFilesystemPath(): void
    {
        $this->createReport();
        $name = $this->createCsvExport();
        unlink(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . $name);

        $this->assertNotFoundWithoutPath(fn () => $this->reportController()->downloadCsvAction($this->request(['exportFile' => $name])));
    }

    public function testControlXliffDownloadOfExistingExportReturnsThatFile(): void
    {
        $this->translationController()->xliffExportAction(
            $this->request(['id' => self::KNOWN_ID, 'data' => json_encode([['type' => 'document', 'id' => $this->page->getId()]], JSON_THROW_ON_ERROR), 'source' => 'en', 'target' => 'de']),
            $this->exportService(),
        );

        $response = $this->translationController()->xliffExportDownloadAction(
            $this->request(['id' => self::KNOWN_ID]),
            $this->exportService()->getTranslationExporter(),
            $this->exportService(),
        );

        $this->assertSame(realpath($this->xliffFile(self::KNOWN_ID)), $response->getFile()->getRealPath());
        $this->assertStringContainsString('pd-sec-pathdisclosure-title', (string) file_get_contents($this->xliffFile(self::KNOWN_ID)));
    }

    private function assertNotFoundWithoutPath(callable $action): void
    {
        $thrown = null;
        $returned = null;

        try {
            $returned = $action();
        } catch (\Throwable $e) {
            $thrown = $e;
        }

        $this->assertInstanceOf(\Symfony\Component\HttpKernel\Exception\NotFoundHttpException::class, $thrown, null === $thrown ? 'No exception; returned ' . get_debug_type($returned) : get_class($thrown) . ': ' . $thrown->getMessage());
        $this->assertStringNotContainsString(PIMCORE_SYSTEM_TEMP_DIRECTORY, $thrown->getMessage());
    }

    /**
     * @param array<string, string> $parameters
     */
    private function request(array $parameters): \Symfony\Component\HttpFoundation\Request
    {
        return new \Symfony\Component\HttpFoundation\Request($parameters);
    }

    private function createCsvExport(): string
    {
        $response = $this->reportController()->createCsvAction(new \Symfony\Component\HttpFoundation\Request(['name' => self::REPORT_NAME, 'headers' => 1, 'drillDownFilters' => '[]']));

        $name = json_decode((string) $response->getContent(), true, 512, JSON_THROW_ON_ERROR)['exportFile'];
        $this->exportFiles[] = $name;

        return $name;
    }

    private function createReport(): void
    {
        $now = time();

        \Pimcore\Model\Tool\SettingsStore::set(
            self::REPORT_NAME,
            json_encode([
                'name' => self::REPORT_NAME,
                'niceName' => 'pd-sec path disclosure report',
                'dataSourceConfig' => [['type' => 'sql', 'sql' => 'id, note', 'from' => $this->reportTable(), 'where' => '', 'groupby' => '']],
                'columnConfiguration' => [
                    ['name' => 'id', 'display' => true, 'export' => true, 'order' => true, 'label' => 'id'],
                    ['name' => 'note', 'display' => true, 'export' => true, 'order' => true, 'label' => 'note'],
                ],
                'shareGlobally' => true,
                'sharedUserNames' => [],
                'sharedRoleNames' => [],
                'menuShortcut' => false,
                'creationDate' => $now,
                'modificationDate' => $now,
            ], JSON_THROW_ON_ERROR),
            'string',
            'pimcore_custom_reports',
        );
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

    private function translationController(): \Pimcore\Bundle\AdminBundle\Controller\Admin\TranslationController
    {
        $controller = new \Pimcore\Bundle\AdminBundle\Controller\Admin\TranslationController();
        $this->wire($controller);

        return $controller;
    }

    private function reportController(): \Pimcore\Bundle\AdminBundle\Controller\Reports\CustomReportController
    {
        $controller = new \Pimcore\Bundle\AdminBundle\Controller\Reports\CustomReportController();
        $this->wire($controller);

        return $controller;
    }

    private function wire(\Pimcore\Bundle\AdminBundle\Controller\AdminAbstractController $controller): void
    {
        $container = \Pimcore::getContainer();

        $controller->setContainer($container);
        $controller->setTokenResolver($container->get(\Pimcore\Security\User\TokenStorageUserResolver::class));
        $controller->setPimcoreSerializer($container->get(\Pimcore\Serializer\Serializer::class));
    }

    private function xliffFile(string $id): string
    {
        return PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . $id . '.xliff';
    }

    private function traversalFile(): string
    {
        return $this->xliffFile(self::TRAVERSAL_ID);
    }

    private function removeFixtures(): void
    {
        foreach ([self::KNOWN_ID, self::UNKNOWN_ID, self::TRAVERSAL_ID] as $id) {
            @unlink($this->xliffFile($id));
        }

        foreach ($this->exportFiles as $name) {
            @unlink(PIMCORE_SYSTEM_TEMP_DIRECTORY . '/' . $name);
        }
        $this->exportFiles = [];

        \Pimcore\Model\Tool\SettingsStore::delete(self::REPORT_NAME, 'pimcore_custom_reports');

        try {
            $this->deleteUserByName(self::ADMIN_USERNAME);
        } finally {
            $page = \Pimcore\Model\Document::getByPath('/' . self::PAGE_KEY);
            $page?->delete();
        }
    }
}
