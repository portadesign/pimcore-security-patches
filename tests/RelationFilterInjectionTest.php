<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2025-27617')]
final class RelationFilterInjectionTest extends \PHPUnit\Framework\TestCase
{
    public function testManyToOneEqualsOperatorQuoteBreakoutMatchesNothing(): void
    {
        $condition = $this->fieldDefinition('manufacturer')->getFilterCondition("x',(SELECT 1),'", '=', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);

        $this->assertSame([], $rows);
    }

    public function testManyToManyObjectLikeOperatorQuoteBreakoutMatchesNothing(): void
    {
        $condition = $this->fieldDefinition('categories')->getFilterCondition("559',(SELECT 1),'", 'LIKE', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);

        $this->assertSame([], $rows);
    }

    public function testControlManufacturerIdMatchesKnownRows(): void
    {
        $condition = $this->fieldDefinition('manufacturer')->getFilterCondition('4', '=', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);
        $expected = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE manufacturer__id = 4');

        $this->assertNotEmpty($expected);
        $this->assertSame($expected, $rows);
    }

    public function testControlCategoryMatchesKnownRows(): void
    {
        $condition = $this->fieldDefinition('categories')->getFilterCondition('559', 'LIKE', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);
        $expected = \Pimcore\Db::get()->fetchFirstColumn("SELECT oo_id FROM object_query_CAR WHERE categories LIKE '%,559,%'");

        $this->assertNotEmpty($expected);
        $this->assertSame($expected, $rows);
    }

    private function fieldDefinition(string $name): \Pimcore\Model\DataObject\ClassDefinition\Data
    {
        $field = \Pimcore\Model\DataObject\ClassDefinition::getById('CAR')->getFieldDefinition($name);

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Data::class, $field);

        return $field;
    }
}
