<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2026-115890')]
final class FieldCollectionJoinTest extends \PHPUnit\Framework\TestCase
{
    private const COLLECTION = 'DataQualityFieldDefinition';

    /**
     * @return array<string, array{string}>
     */
    public static function fieldnameProvider(): array
    {
        return [
            'quote breakout with always-true condition' => ['" OR 1=1 OR "'],
            'quote breakout with sleep' => ['x" AND SLEEP(5)-- '],
            'stacked statement' => ['x"; SELECT password FROM users; -- '],
            'trailing backslash' => ['\\'],
            'single quote' => ["x' OR '1'='1"],
            'backtick' => ['x` OR 1=1 OR `'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('fieldnameProvider')]
    public function testFieldnameIsQuotedAsStringLiteral(string $fieldname): void
    {
        $sql = $this->joinSql($fieldname);
        $db = \Pimcore\Db::get();
        $alias = $db->quoteIdentifier(self::COLLECTION . '~' . $fieldname);

        $this->assertStringContainsString($alias . '.fieldname = ' . $db->quote($fieldname), $sql);
    }

    public function testPlainFieldnameStillJoinsOnFieldname(): void
    {
        $sql = $this->joinSql('items');

        $this->assertMatchesRegularExpression('/`' . self::COLLECTION . '~items`\.fieldname = [\'"]items[\'"]/', $sql);
        $this->assertStringContainsString('`' . self::COLLECTION . '~items`.id = ', $sql);
    }

    public function testJoinWithoutFieldnameHasNoFieldnameCondition(): void
    {
        $sql = $this->joinSql(null);

        $this->assertStringNotContainsString('.fieldname', $sql);
        $this->assertStringContainsString('`' . self::COLLECTION . '`.id = ', $sql);
    }

    private function joinSql(?string $fieldname): string
    {
        $listing = new \Pimcore\Model\DataObject\DataQualityConfig\Listing();
        $listing->addFieldCollection(self::COLLECTION, $fieldname);
        $dao = $listing->getDao();
        \assert($dao instanceof \Pimcore\Model\DataObject\Listing\Concrete\Dao);

        $queryBuilder = \Pimcore\Db::get()->createQueryBuilder();
        $queryBuilder->select('1')->from($dao->getTableName());
        (new \ReflectionMethod($dao, 'applyJoins'))->invoke($dao, $queryBuilder);

        return $queryBuilder->getSQL();
    }
}
