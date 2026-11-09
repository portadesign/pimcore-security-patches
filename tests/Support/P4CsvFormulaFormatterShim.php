<?php

declare(strict_types=1);

namespace Pimcore\Helper;

if (!class_exists(\Pimcore\Helper\CsvFormulaFormatter::class, false)) {
    class CsvFormulaFormatter extends \League\Csv\EscapeFormula
    {
        public function unEscapeField(mixed $field): mixed
        {
            if (is_string($field)
                && isset($field[0], $field[1])
                && $field[0] === $this->getEscape()
                && in_array($field[1], $this->getSpecialCharacters())
            ) {
                return ltrim($field, $field[0]);
            }

            return $field;
        }
    }
}
