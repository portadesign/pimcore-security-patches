<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-44739')]
final class CustomReportsKeywordGuardTest extends \PHPUnit\Framework\TestCase
{
    use \Portadesign\PimcoreSecurityPatches\Tests\Support\ReportScratchTable;

    protected function setUp(): void
    {
        $this->createReportScratchTable();
    }

    protected function tearDown(): void
    {
        $this->dropReportScratchTable();
    }

    /**
     * @return array<string, array{string}>
     */
    public static function hiddenKeywordProvider(): array
    {
        return [
            'drop followed by tab' => ["'DROP\tTABLE x'"],
            'update followed by newline' => ["'UPDATE\nx SET y'"],
            'delete followed by carriage return' => ["'DELETE\rFROM x'"],
            'drop split from table by inline comment' => ["'DROP/**/TABLE x'"],
            'versioned comment around keyword' => ["'/*!50000DELETE*/FROM x'"],
            'truncate with multiline comment' => ["'TRUNCATE/*\n*/x'"],
            'plain drop followed by space' => ["'drop x'"],
            'plain delete followed by space' => ["'delete x'"],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('hiddenKeywordProvider')]
    public function testGetColumnsRefusesKeywordHiddenBehindWhitespaceOrComment(string $literal): void
    {
        $config = $this->reportConfig(['sql' => $literal . ' AS probe', 'from' => '']);

        $this->expectException(\Exception::class);
        $this->expectExceptionMessageMatches("/^Only 'SELECT' statements are allowed!/");

        $this->reportAdapter($config)->getColumns($config);
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('hiddenKeywordProvider')]
    public function testGetDataRefusesKeywordHiddenBehindWhitespaceOrComment(string $literal): void
    {
        $config = $this->reportConfig(['sql' => $literal . ' AS probe', 'from' => '']);

        $result = $this->reportAdapter($config)->getData([], null, null, 0, 10);

        $this->assertSame(['data' => [], 'total' => 0], $result);
    }

    /**
     * @return array<string, array{string}>
     */
    public static function keywordInsideIdentifierProvider(): array
    {
        return [
            'drop after dollar' => ['$drop'],
            'drop after letter' => ['xdrop'],
            'update after dollar' => ['$update'],
            'delete after letter' => ['xdelete'],
            'quoted drop' => ['`drop`'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('keywordInsideIdentifierProvider')]
    public function testGetColumnsAcceptsKeywordInsideLargerIdentifier(string $alias): void
    {
        $config = $this->reportConfig(['sql' => 'id AS ' . $alias, 'where' => 'id = 3']);

        $this->assertSame([trim($alias, '`')], $this->reportAdapter($config)->getColumns($config));
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('keywordInsideIdentifierProvider')]
    public function testGetDataAcceptsKeywordInsideLargerIdentifier(string $alias): void
    {
        $config = $this->reportConfig(['sql' => 'id AS ' . $alias, 'where' => 'id = 3']);

        $result = $this->reportAdapter($config)->getData([], null, null, 0, 10);

        $this->assertSame([[trim($alias, '`') => '3']], array_map(
            static fn (array $row): array => array_map('strval', $row),
            $result['data'],
        ));
    }

    public function testKeywordPrefixedIdentifiersStillRun(): void
    {
        $config = $this->reportConfig(['sql' => 'id, updated_at', 'where' => 'id = 3']);

        $this->assertSame(['id', 'updated_at'], $this->reportAdapter($config)->getColumns($config));
    }
}
