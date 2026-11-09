<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('CVE-2023-47637')]
final class MultiselectFilterInjectionTest extends \PHPUnit\Framework\TestCase
{
    public function testEqualsOperatorQuoteBreakoutYieldsNoMatchWithoutThrowing(): void
    {
        $condition = $this->fieldDefinition()->getFilterCondition("red',(SELECT 1),'", '=', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);

        $this->assertSame([], $rows);
    }

    public function testCommaBoundaryValueDoesNotMatchAnyRow(): void
    {
        $condition = $this->fieldDefinition()->getFilterCondition('a,b', '=', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);

        $this->assertSame([], $rows);
    }

    public function testControlLikeMatchesKnownRedRow(): void
    {
        $condition = $this->fieldDefinition()->getFilterCondition('red', 'LIKE', []);

        $rows = \Pimcore\Db::get()->fetchFirstColumn('SELECT oo_id FROM object_query_CAR WHERE ' . $condition);
        $expected = \Pimcore\Db::get()->fetchFirstColumn("SELECT oo_id FROM object_query_CAR WHERE color LIKE '%,red,%'");

        $this->assertNotEmpty($expected);
        $this->assertSame($expected, $rows);
    }

    private function fieldDefinition(): \Pimcore\Model\DataObject\ClassDefinition\Data\Multiselect
    {
        $field = \Pimcore\Model\DataObject\ClassDefinition::getById('CAR')->getFieldDefinition('color');

        $this->assertInstanceOf(\Pimcore\Model\DataObject\ClassDefinition\Data\Multiselect::class, $field);

        return $field;
    }
}
