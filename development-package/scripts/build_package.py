"""Build the offline review bundle and archive after a successful validate_package run.

Order: copy the source transcript, run validate_package, then write VALIDATION.md, REVIEW-BUNDLE.md,
manifest.json and the ZIP. All numbers in VALIDATION.md come from the validation summary.
"""
import sys

sys.dont_write_bytecode = True
from pathlib import Path  # noqa: E402

sys.path[:0] = [str(Path(__file__).resolve().parent)]
from datetime import date  # noqa: E402
import hashlib  # noqa: E402
import json  # noqa: E402
import zipfile  # noqa: E402

import validate_package  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
VERSION = '0.2.0'
DATE = '2026-10-13'
MONTHS = ('', 'января', 'февраля', 'марта', 'апреля', 'мая', 'июня', 'июля', 'августа', 'сентября',
          'октября', 'ноября', 'декабря')
INDENT = '  '


def human_date(value):
    parsed = date.fromisoformat(value)
    return f'{parsed.day} {MONTHS[parsed.month]} {parsed.year} года'


def copy_transcript():
    source = ROOT.parent / 'sikkerheit-app-chat-transcript.md'
    target = ROOT / 'source' / 'boss-chat.md'
    target.parent.mkdir(exist_ok=True)
    if source.exists():
        target.write_bytes(source.read_bytes())
    return target


def validation_text(summary):
    standard = ('Стандартная проверка выполнена: jsonschema и openapi-spec-validator с проверкой format.'
                if summary.get('standardValidation') else
                'Стандартная проверка не выполнена: jsonschema и openapi-spec-validator не установлены. '
                'Выполнена только встроенная проверка подмножества JSON Schema.')
    s = summary
    return f'''# Проверка Development Package

Версия {VERSION}, дата {DATE}. Проверку выполняет `scripts/validate_package.py`; он ничего не записывает. `scripts/build_package.py` вызывает его первым и пишет этот файл, `REVIEW-BUNDLE.md`, `manifest.json` и архив только после успешной проверки.

- Прочитаны все JSON-файлы и разрешены локальные ссылки `$ref`; в `openapi.json` нет внешних ссылок, у отдельных схем агента есть `$id`.
- Каталог: уникальных check IDs — {s["checkIds"]}, из них WIN-* — {s["agentCheckIds"]}; у каждой проверки есть строка в `03`, объект и режим по умолчанию совпадают с каталогом.
- Документы: функциональных требований с колонкой «Контракт» — {s["requirements"]}, приёмочных сценариев — {s["acceptance"]}, runbooks — {s["runbooks"]}; ссылки на ID разрешаются в определения.
- Синтетические scan batch (всего {s["examples"]}) проходят схему и семантическую проверку, каждый содержит ровно все WIN-*; основной пример содержит эталонный случай BitLocker.
- Отклонены все отрицательные варианты (всего {s["negativeVariants"]}); положительные варианты SAFE_TEXT приняты (всего {s["positiveVariants"]}).
- Операции OpenAPI: всего {s["operations"]} (агентских {s["agentOperations"]}, портальных {s["portalOperations"]}); проверены path parameters, security, CSRF, отдельный mTLS host, `x-audit-read`, `Accept-Language`, роли и заголовки выдачи отчёта.
- Ответы: коды `Problem.code` (всего {s["problemCodes"]}) совпадают с таблицей `05`, действия агента (всего {s["agentActions"]}) образуют закрытый перечень; наборы статусов операций соответствуют правилам.
- `Assessment.reasonCode`: значений — {s["reasonCodes"]}; события `finding_event` совпадают с таблицей `05`.
- Реестр инвариантов: записей — {s["invariants"]} (P1 — {s["invariantsP1"]}, P2 — {s["invariantsP2"]}); поля, формы `expectedError`, разделы источников и покрытие проверены.
- Проверены локальные Markdown-ссылки, закрытие code fences и число сообщений исходной переписки ({s["chatMessages"]}).

{standard} Полная стандартная проверка, пробная генерация клиентов C# и TypeScript и CI — первый результат WP-01.

Приёмочные сценарии Windows/Azure/Entra, работоспособность API, производительность, стоимость и юридические условия подтверждаются на соответствующих этапах. Данные примеров синтетические; клиентские системы не использовались.
'''


def write_bundle(source_copy):
    docs = [ROOT / 'README.md'] + sorted(ROOT.glob('[0-9][0-9]-*.md')) + [source_copy, ROOT / 'VALIDATION.md']
    parts = ['# Development Package для независимой оценки\n\n'
             f'Версия {VERSION} от {human_date(DATE)}. Полный комплект требований, '
             'архитектуры и предложенных контрактов.\n\n'
             'Рецензент начинает с запроса независимой оценки и проверяет весь комплект.\n']
    for file in docs:
        parts.append(f'\n\nФайл `{file.relative_to(ROOT).as_posix()}`\n\n' + file.read_text(encoding='utf-8'))
    for file in sorted((ROOT / 'specs').glob('*.json')) + sorted((ROOT / 'examples').glob('*.json')):
        parts.append(f'\n\nФайл `{file.relative_to(ROOT).as_posix()}`\n\n```json\n'
                     + file.read_text(encoding='utf-8') + '```\n')
    bundle = ROOT / 'REVIEW-BUNDLE.md'
    bundle.write_text(''.join(parts), encoding='utf-8')
    return bundle


def write_archive():
    files = sorted(p for p in ROOT.rglob('*') if p.is_file() and p.name != 'manifest.json'
                   and '__pycache__' not in p.parts)
    manifest = {'packageVersion': VERSION, 'date': DATE, 'timezone': 'Europe/Oslo',
                'files': [{'path': p.relative_to(ROOT).as_posix(), 'bytes': p.stat().st_size,
                           'sha256': hashlib.sha256(p.read_bytes()).hexdigest()} for p in files]}
    (ROOT / 'manifest.json').write_text(json.dumps(manifest, ensure_ascii=False, indent=INDENT) + '\n',
                                        encoding='utf-8')
    archive = ROOT.parent / f'sikkerheit-development-package-v{VERSION}.zip'
    with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED) as handle:
        for file in files + [ROOT / 'manifest.json']:
            handle.write(file, 'development-package/' + file.relative_to(ROOT).as_posix())
    with zipfile.ZipFile(archive) as handle:
        assert handle.testzip() is None, 'Archive is corrupted'
        for entry in manifest['files']:
            data = handle.read('development-package/' + entry['path'])
            assert hashlib.sha256(data).hexdigest() == entry['sha256'], f'Archive mismatch: {entry["path"]}'
    return archive, files


def main():
    source_copy = copy_transcript()
    report = validate_package.run(ROOT)
    if report.errors:
        for category, message in report.errors:
            print(f'[{category}] {message}', file=sys.stderr)
        print('Сборка остановлена: проверка пакета не пройдена.', file=sys.stderr)
        return True
    (ROOT / 'VALIDATION.md').write_text(validation_text(report.summary), encoding='utf-8')
    bundle = write_bundle(source_copy)
    archive, files = write_archive()
    print(json.dumps({'packageVersion': VERSION, 'files': len(files + [ROOT / 'manifest.json']),
                      'apiOperations': report.summary['operations'], 'archiveBytes': archive.stat().st_size,
                      'bundleBytes': bundle.stat().st_size, 'archive': str(archive), 'bundle': str(bundle)},
                     ensure_ascii=False, indent=INDENT))
    return False


if __name__ == '__main__':
    sys.exit(main())
