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
VERSION = '0.3.1'
DATE = '2026-10-16'
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

- Состав каталога соответствует белому списку путей пакета, скрытые файлы и `__pycache__` в пакет не входят; версия совпадает в `build_package.py`, `contract_catalog.py`, `README.md` и `09`. Проверка читает только файлы внутри пакета, локальные ссылки документов его не покидают. `manifest.json` записывается после проверки; `validate_package.py --manifest` сверяет с ним размер и SHA-256 каждого файла полученного пакета и находит лишние и недостающие файлы.
- Прочитаны все JSON-файлы и разрешены локальные ссылки `$ref`; в `openapi.json` нет внешних ссылок, у четырёх отдельных схем (агент и Microsoft 365) есть `$id`.
- Каталог: уникальных check IDs — {s["checkIds"]}, из них M365-* — {s["graphCheckIds"]}, WIN-* — {s["agentCheckIds"]}; у каждой проверки есть строка в `03`, объект и режим по умолчанию совпадают с каталогом; этап проверки следует из источника (M365 — P1, Windows — P2).
- Документы: функциональных требований с колонкой «Контракт» — {s["requirements"]}, приёмочных сценариев — {s["acceptance"]}, runbooks — {s["runbooks"]}; каждая операция OpenAPI входит в «Контракт» ровно своего этапа; ссылки на ID разрешаются в определения; порядок `retention_purge` в `04` и `05` совпадает с контрактом; права Graph в `04` совпадают с каталогом (всего {s["graphPermissions"]}); строки плана приёмки суммируются в итоги этапов (P1 — {s["acceptanceHours"]["P1"]}, P2 — {s["acceptanceHours"]["P2"]} часов приёмки), а каждый отрезок календаря — в свои часы и календарные недели при {s["acceptanceHoursPerWeek"]} часах приёмки в неделю.
- Этапы: у каждого приёмочного сценария есть этап P1, P2 или обе части; требования, записи реестра инвариантов и условия допуска ссылаются только на сценарии своего этапа; операции runbooks существуют и не относятся к более позднему этапу; таблица состояний агента в `05` совпадает с каталогом.
- Таблица жизненного цикла ОС: строк — {s["osLifecycleRows"]}; семейства совпадают с каталогом; каждое `servicingEndsAt` равно началу следующего дня по America/Los_Angeles в UTC.
- Синтетические примеры (всего {s["examples"]}): два пакета агента содержат ровно все WIN-* и проходят схему и семантическую проверку, основной содержит эталонный случай BitLocker; запуск сбора M365 покрывает все собираемые M365-* (у отложенной M365-007 модуль `skipped` и наблюдений нет) и содержит эталонный случай report-only для M365-003.
- Отклонены все отрицательные варианты (всего {s["negativeVariants"]}: пакеты агента, запуски M365 и тела `createPolicyRevision`); положительные варианты (SAFE_TEXT, WIN-006 без успешного поиска, норвежский UPN) приняты (всего {s["positiveVariants"]}).
- Операции OpenAPI: всего {s["operations"]} (P1 — {s["operationsP1"]}, P2 — {s["operationsP2"]}; агентских {s["agentOperations"]}, портальных {s["portalOperations"]}); проверены path parameters, `x-phase`, security, CSRF, hostname агента, роли, `x-audit-read`, `Accept-Language` и заголовки выдачи отчёта.
- Ответы: коды `Problem.code` (всего {s["problemCodes"]}) совпадают с таблицей `05`, действия агента (всего {s["agentActions"]}) образуют закрытый перечень; наборы статусов операций соответствуют правилам.
- `Assessment.reasonCode`: значений — {s["reasonCodes"]}; события `finding_event` совпадают с таблицей `05`.
- Реестр инвариантов: записей — {s["invariants"]} (P1 — {s["invariantsP1"]}, P2 — {s["invariantsP2"]}); проверены поля, формы `expectedError`, разделы источников, покрытие кодов Problem, reasonCode, строк событий, обеих ветвей `assessmentMode` и каждой проверки в режиме assessed. Полноту правил число записей не доказывает.
- Проверены локальные Markdown-ссылки и закрытие code fences; копия переписки `source/boss-chat.md` совпадает с SHA-256, закреплённым в `scripts/validate_docs.py`, и содержит {s["chatMessages"]} сообщений.

{standard} Полная стандартная проверка, пробная генерация клиентов C# и TypeScript и CI — первый результат WP-01.

Приёмочные сценарии Microsoft 365, Windows и Azure, работоспособность API, производительность, стоимость и юридические условия подтверждаются на соответствующих этапах. Данные примеров синтетические; клиентские системы не использовались.
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
    files = [p for p in validate_package.package_files(ROOT) if p.relative_to(ROOT).as_posix() != 'manifest.json']
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
    written = validate_package.Report()
    validate_package.check_manifest(written, ROOT, strict=True)
    assert not written.errors, f'manifest.json does not match the package: {written.errors}'
    print(json.dumps({'packageVersion': VERSION, 'files': len(files + [ROOT / 'manifest.json']),
                      'apiOperations': report.summary['operations'], 'archiveBytes': archive.stat().st_size,
                      'bundleBytes': bundle.stat().st_size, 'archive': str(archive), 'bundle': str(bundle)},
                     ensure_ascii=False, indent=INDENT))
    return False


if __name__ == '__main__':
    sys.exit(main())
