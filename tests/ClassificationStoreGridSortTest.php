<?php

declare(strict_types=1);

namespace Portadesign\PimcoreSecurityPatches\Tests;

#[\PHPUnit\Framework\Attributes\Group('PD-2026-007')]
final class ClassificationStoreGridSortTest extends \PHPUnit\Framework\TestCase
{
    public function testControlRealClassificationStoreSortLoadsRows(): void
    {
        $this->assertCount(5, $this->load('~classificationstore~technicalAttributes~1-1'));
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidSortProvider(): array
    {
        return [
            'tail with a space after a real field name' => ['~classificationstore~technicalAttributes_x y~1-1'],
            'tail that is not a field name' => ['~classificationstore~technicalAttributes_zz~1-1'],
            'unknown field' => ['~classificationstore~nosuchfield~1-1'],
        ];
    }

    #[\PHPUnit\Framework\Attributes\DataProvider('invalidSortProvider')]
    public function testInvalidClassificationStoreSortIsRejectedBeforeAnyQuery(string $property): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('Invalid classification store sort.');

        $this->load($property);
    }

    /**
     * @return list<\Pimcore\Model\DataObject\Concrete>
     */
    private function load(string $property): array
    {
        $admin = \Pimcore\Model\User::getByName('admin');
        $this->assertInstanceOf(\Pimcore\Model\User::class, $admin);

        $list = (new \Pimcore\Bundle\AdminBundle\Helper\GridHelperService())->prepareListingForGrid(
            [
                'folderId' => 1,
                'classId' => 'AP',
                'start' => 0,
                'limit' => 5,
                'sort' => json_encode([['property' => $property, 'direction' => 'ASC']], JSON_THROW_ON_ERROR),
            ],
            'en',
            $admin,
        );

        return $list->load();
    }
}
