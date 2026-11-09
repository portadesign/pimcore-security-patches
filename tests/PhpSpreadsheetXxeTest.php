<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('GHSA-hq76-662x-7mw4')]
final class PhpSpreadsheetXxeTest extends \PHPUnit\Framework\TestCase
{
    private const FLOOR = '1.30.7';

    private const SINGLE_QUOTED_UTF7_DOCTYPE = '<?xml version="1.0" encoding=\'UTF-7\'?>' . "\n" . '+ADw-!DOCTYPE sst [<!ENTITY xxe "x">]>' . "\n" . '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1"><si><t>&xxe;</t></si></sst>';

    private const DOUBLE_QUOTED_UTF7_DOCTYPE = '<?xml version="1.0" encoding="UTF-7"?>' . "\n" . '+ADw-!DOCTYPE sst [<!ENTITY xxe "x">]>' . "\n" . '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" count="1" uniqueCount="1"><si><t>&xxe;</t></si></sst>';

    private string $workbook = '';

    protected function tearDown(): void
    {
        if ('' !== $this->workbook && is_file($this->workbook)) {
            unlink($this->workbook);
        }
    }

    public function testControlInstalledVersionIsNotBelowFloor(): void
    {
        $installed = \Composer\InstalledVersions::getVersion('phpoffice/phpspreadsheet');

        $this->assertNotNull($installed);
        $this->assertTrue(
            version_compare($installed, self::FLOOR, '>='),
            sprintf('phpoffice/phpspreadsheet %s is below %s; run composer update phpoffice/phpspreadsheet', $installed, self::FLOOR),
        );
    }

    /**
     * @return array<string, array{string, bool}>
     */
    public static function conflictProvider(): array
    {
        return [
            'before the advisory fix' => ['1.29.0', true],
            'advisory fix, below the floor' => ['1.29.1', true],
            'last version below the floor' => ['1.30.6', true],
            'floor' => ['1.30.7', false],
            'above the floor' => ['1.30.8', false],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('conflictProvider')]
    public function testComposerConflictRejectsVersionsBelowFloor(string $version, bool $conflicts): void
    {
        $constraint = $this->conflictConstraint();

        $this->assertSame(1, preg_match('/^<\s*(\d+(?:\.\d+)*)$/', $constraint, $matches), 'conflict constraint is not of the form <x.y.z: ' . $constraint);
        $this->assertSame($conflicts, version_compare($version, $matches[1], '<'));
    }

    public function testScannerRejectsDoctypeHiddenByUtf7BehindSingleQuotedEncoding(): void
    {
        $this->expectException(\PhpOffice\PhpSpreadsheet\Reader\Exception::class);

        $this->scanner()->scan(self::SINGLE_QUOTED_UTF7_DOCTYPE);
    }

    public function testControlScannerRejectsDoctypeHiddenByUtf7BehindDoubleQuotedEncoding(): void
    {
        $this->expectException(\PhpOffice\PhpSpreadsheet\Reader\Exception::class);

        $this->scanner()->scan(self::DOUBLE_QUOTED_UTF7_DOCTYPE);
    }

    public function testXlsxWithHiddenDoctypeInSharedStringsIsNotLoaded(): void
    {
        $this->workbook = $this->buildWorkbook(self::SINGLE_QUOTED_UTF7_DOCTYPE);

        $this->expectException(\PhpOffice\PhpSpreadsheet\Reader\Exception::class);

        \PhpOffice\PhpSpreadsheet\IOFactory::load($this->workbook);
    }

    private function conflictConstraint(): string
    {
        $composer = json_decode((string) file_get_contents(dirname(__DIR__) . '/composer.json'), true, 512, JSON_THROW_ON_ERROR);
        $constraint = $composer['conflict']['phpoffice/phpspreadsheet'] ?? null;

        if (null === $constraint && false !== getenv('PD_COMPOSER_CONFLICT_MANIFEST')) {
            $manifest = json_decode((string) file_get_contents((string) getenv('PD_COMPOSER_CONFLICT_MANIFEST')), true, 512, JSON_THROW_ON_ERROR);
            $constraint = $manifest['composer_conflict']['phpoffice/phpspreadsheet'] ?? null;
        }

        $this->assertIsString($constraint, 'composer.json declares no conflict for phpoffice/phpspreadsheet');

        return $constraint;
    }

    private function scanner(): \PhpOffice\PhpSpreadsheet\Reader\Security\XmlScanner
    {
        return \PhpOffice\PhpSpreadsheet\Reader\Security\XmlScanner::getInstance(new \PhpOffice\PhpSpreadsheet\Reader\Xlsx());
    }

    private function buildWorkbook(string $sharedStrings): string
    {
        $path = sys_get_temp_dir() . '/pd_sec_xxe_' . bin2hex(random_bytes(6)) . '.xlsx';
        $parts = [
            '[Content_Types].xml' => '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"><Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/><Default Extension="xml" ContentType="application/xml"/><Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/><Override PartName="/xl/worksheets/sheet1.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/><Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/></Types>',
            '_rels/.rels' => '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>',
            'xl/workbook.xml' => '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>',
            'xl/_rels/workbook.xml.rels' => '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet1.xml"/><Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/sharedStrings" Target="sharedStrings.xml"/></Relationships>',
            'xl/worksheets/sheet1.xml' => '<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData><row r="1"><c r="A1" t="s"><v>0</v></c></row></sheetData></worksheet>',
            'xl/sharedStrings.xml' => $sharedStrings,
        ];

        $zip = new \ZipArchive();
        $zip->open($path, \ZipArchive::CREATE | \ZipArchive::OVERWRITE);
        foreach ($parts as $name => $body) {
            $zip->addFromString($name, $body);
        }
        $zip->close();

        return $path;
    }
}
