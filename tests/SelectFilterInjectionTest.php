<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-003')]
final class SelectFilterInjectionTest extends \PHPUnit\Framework\TestCase
{
    public function testEqualsOperatorQuoteBreakoutMatchesNothing(): void
    {
        $condition = $this->fieldDefinition()->getFilterCondition('sports car",(SELECT 1),"', '=', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);

        $this->assertSame([], $rows);
    }

    public function testControlLikeMatchesAllSportsCarRows(): void
    {
        $condition = $this->fieldDefinition()->getFilterCondition('sports', 'LIKE', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);
        $expected = \Pimcore\Db::get()->fetchFirstColumn("SELECT oo_id FROM object_query_CAR WHERE carClass LIKE '%sports%'");

        $this->assertNotEmpty($expected);
        $this->assertSame($expected, $rows);
    }

    private function fieldDefinition(): \Pimcore\Model\DataObject\ClassDefinition\Data\Select
    {
        $field = \Pimcore\Model\DataObject\ClassDefinition::getById('CAR')->getFieldDefinition('carClass');

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Data\Select::class, $field);

        return $field;
    }
}
