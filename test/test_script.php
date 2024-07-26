<?php
// /app/test/test_script.php

// ANSI escape codes для цветного текста
const GREEN = "\033[32m";
const RED = "\033[31m";
const RESET = "\033[0m";

// Функция для выполнения команды и возврата вывода
function executeCommand($command) {
    $output = [];
    exec($command, $output, $returnCode);
    return [
        'output' => implode("\n", $output),
        'return_code' => $returnCode
    ];
}

// Открытие CSV файла с тестовыми данными
$csvFile = fopen('test/test_data.csv', 'r');
if ($csvFile === false) {
    die("Не удалось открыть test_data.csv");
}

$headers = fgetcsv($csvFile); // Считываем заголовки, но они нам не нужны

// Перебор строк CSV файла
while (($row = fgetcsv($csvFile)) !== false) {
    $emlFile = $row[0];
    $expectedOutput = $row[1];

    // Формирование команды для запуска скрипта Symfony
    $command = "php bin/console eml:check $emlFile";

    // Выполнение команды
    $result = executeCommand($command);

    // Проверка результата
    $testResult = "";
    if ($result['return_code'] > 0 && strpos($result['output'], 'IP-адрес отправителя не найден в заголовке Received.') !== false) {
        $testResult = RED . "FAIL" . RESET;
    } else {
        $testResult = GREEN . "OK" . RESET;
    }

    // Вывод имени файла, ожидаемого результата и результата теста
    echo "$emlFile:\t$testResult\n";
}

fclose($csvFile);