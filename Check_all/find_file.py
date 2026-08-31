"""
Оркестратор статического аудитора безопасности инфраструктуры.

Находит конфигурационные файлы, запускает проверки выбранного уровня
(easy / medium / hard) и возвращает структурированный AuditReport,
пригодный для сериализации в JSON и использования как из CLI, так и
из внешнего кода (например, веб-API).

╔══════════════════════════════════════════════════════════════════╗
║  ВАЖНОЕ ОГРАНИЧЕНИЕ АРХИТЕКТУРЫ                                   ║
╚══════════════════════════════════════════════════════════════════╝
Easy_Check.all_easy_check(), Medium_Check.all_medium_check() и
Hard_Check.all_hard_check() сейчас только печатают отчёт в stdout —
они не возвращают структурированные данные. Чтобы не менять эти три
модуля (это отдельная задача), audit_project() перехватывает их
stdout и восстанавливает из него объекты Finding через парсинг.

Из этого вытекают два осознанных ограничения, пока Easy/Medium/Hard
не начнут возвращать данные напрямую:

  1. check_id — это не официальный идентификатор проверки (его нет
     в печатаемом отчёте), а слаг, построенный из заголовка находки.
  2. Для medium/hard проверки запускаются на всю папку одним вызовом,
     поэтому конкретный file_path для каждой находки внутри такого
     батча недоступен — используется путь папки с пометкой batch.
  3. Hard_Check.py сейчас полностью состоит из заглушек (не читает
     файлы, всегда печатает один и тот же демонстрационный пример) —
     поэтому его вывод не преобразуется в findings, чтобы не выдавать
     вымышленные результаты; вместо этого делается пометка в errors.
"""

from __future__ import annotations

import argparse
import contextlib
import io
import json
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional

from Easy_Check import all_easy_check
from Medium_Check import all_medium_check
from Hard_Check import all_hard_check


# ==================== КОНСТАНТЫ ====================

IGNORE_DIRS = {
    '.git', 'node_modules', '__pycache__', 'venv', '.venv',
    'dist', 'build', '.terraform', '.idea', '.vscode',
}
TARGET_EXTENSIONS = {'.yaml', '.yml', '.json', '.tf', '.tfvars'}
TARGET_FILES = {
    'Dockerfile', 'docker-compose.yml', 'docker-compose.yaml',
    '.gitlab-ci.yml', 'Jenkinsfile',
}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 МБ

VALID_LEVELS = {'easy', 'medium', 'hard'}


# ==================== СТРУКТУРЫ ДАННЫХ ====================

@dataclass
class Finding:
    """Одна найденная проблема безопасности."""
    level: str            # 'easy' | 'medium' | 'hard'
    severity: str          # 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | ...
    check_id: str           # слаг проверки (см. ограничение в docstring модуля)
    title: str
    file_path: str
    line_num: int
    line_text: str


@dataclass
class AuditReport:
    """Итоговый результат аудита проекта."""
    project_path: str
    levels: List[str]
    files_scanned: int = 0
    findings: List[Finding] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity.upper() == 'CRITICAL')

    def to_dict(self) -> dict:
        """Сериализуемое представление отчёта (для JSON / веб-API)."""
        return {
            'project_path': self.project_path,
            'levels': self.levels,
            'files_scanned': self.files_scanned,
            'total_findings': self.total_findings,
            'critical_count': self.critical_count,
            'findings': [
                {
                    'level': f.level,
                    'severity': f.severity,
                    'check_id': f.check_id,
                    'title': f.title,
                    'file_path': f.file_path,
                    'line_num': f.line_num,
                    'line_text': f.line_text,
                }
                for f in self.findings
            ],
            'errors': self.errors,
        }

    def summary(self) -> str:
        """Человекочитаемая сводка для вывода в консоль."""
        by_severity: Dict[str, int] = defaultdict(int)
        for f in self.findings:
            by_severity[f.severity.upper()] += 1

        lines = [
            '=' * 70,
            '📊 ИТОГОВАЯ СВОДКА АУДИТА',
            '=' * 70,
            f'   Проект: {self.project_path}',
            f'   Уровни: {", ".join(self.levels)}',
            f'   Файлов просканировано: {self.files_scanned}',
            f'   Всего находок: {self.total_findings}',
        ]
        for sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'):
            if by_severity.get(sev):
                lines.append(f'      {sev}: {by_severity[sev]}')
        if self.errors:
            lines.append(f'   Ошибок при проверке: {len(self.errors)}')
            for err in self.errors:
                lines.append(f'      • {err}')
        lines.append('=' * 70)
        return '\n'.join(lines)


# ==================== ПОИСК И ГРУППИРОВКА ФАЙЛОВ ====================

def find_config_files(root_path: str = '.') -> List[Path]:
    """Рекурсивно находит конфигурационные файлы, пригодные для аудита."""
    root = Path(root_path)
    found_files: List[Path] = []

    if not root.exists():
        return found_files

    if root.is_file():
        return [root]

    for file in root.rglob('*'):
        if any(ignored in file.parts for ignored in IGNORE_DIRS):
            continue
        if not file.is_file():
            continue
        if file.name in TARGET_FILES or file.suffix in TARGET_EXTENSIONS:
            try:
                if file.stat().st_size > MAX_FILE_SIZE:
                    continue
            except OSError:
                continue
            found_files.append(file)

    return found_files


def group_files_by_folder(files: List[Path]) -> Dict[Path, List[Path]]:
    """Группирует файлы по родительским папкам (для batch-проверок medium/hard)."""
    files_by_folder: Dict[Path, List[Path]] = defaultdict(list)
    for file in files:
        files_by_folder[file.parent].append(file)
    return dict(files_by_folder)


# ==================== ПАРСИНГ STDOUT В FINDING ====================

_TITLE_RE = re.compile(r'^⚠️\s+\[(?P<severity>[A-ZА-Я]+)\]\s+(?P<title>.+)$')
_LOCATION_RE = re.compile(
    r'^\s*Строка\s+(?P<line>\d+):\s*(?P<text>.+?)(?:\s+←\s+(?P<reason>.+))?\s*$'
)


def _slugify(title: str) -> str:
    """Простой слаг из заголовка находки (используется как check_id-заглушка)."""
    slug = re.sub(r'[^\w]+', '-', title.strip().lower(), flags=re.UNICODE)
    return slug.strip('-') or 'unknown'


def _parse_findings_from_output(output: str, level: str, file_path: str) -> List[Finding]:
    """
    Восстанавливает Finding-объекты из печатаемого отчёта Easy/Medium-проверок.
    См. ограничения в docstring модуля — это лучшее, что можно сделать без
    изменения самих check-модулей.
    """
    findings: List[Finding] = []
    current_severity = 'UNKNOWN'
    current_title = 'Unknown Check'

    for line in output.splitlines():
        title_match = _TITLE_RE.match(line)
        if title_match:
            current_severity = title_match.group('severity')
            current_title = title_match.group('title').strip()
            continue

        loc_match = _LOCATION_RE.match(line)
        if loc_match:
            findings.append(Finding(
                level=level,
                severity=current_severity,
                check_id=_slugify(current_title),
                title=current_title,
                file_path=file_path,
                line_num=int(loc_match.group('line')),
                line_text=loc_match.group('text').strip(),
            ))

    return findings


# ==================== ГЛАВНАЯ ФУНКЦИЯ API ====================

def audit_project(path: str = '.', levels: Optional[List[str]] = None) -> AuditReport:
    """
    Главная точка входа API.

    Args:
        path: путь к проекту или к одному файлу.
        levels: список уровней проверки, например ['easy', 'medium'].
                None означает «все уровни».

    Returns:
        AuditReport со всеми находками и списком ошибок (если какие-то
        файлы/проверки не удалось обработать).
    """
    if levels is None:
        levels = sorted(VALID_LEVELS)
    else:
        levels = [lvl.strip().lower() for lvl in levels]
        invalid = set(levels) - VALID_LEVELS
        if invalid:
            raise ValueError(
                f'Неизвестные уровни проверки: {sorted(invalid)}. '
                f'Допустимые значения: {sorted(VALID_LEVELS)}'
            )

    report = AuditReport(project_path=str(path), levels=levels)

    files = find_config_files(path)
    report.files_scanned = len(files)
    if not files:
        report.errors.append(f'Конфигурационные файлы не найдены по пути: {path}')
        return report

    files_by_folder = group_files_by_folder(files)

    if 'easy' in levels:
        for file in files:
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    all_easy_check(str(file))
            except Exception as e:
                report.errors.append(f'[easy] {file}: {e}')
                continue
            report.findings.extend(
                _parse_findings_from_output(buf.getvalue(), 'easy', str(file))
            )

    if 'medium' in levels:
        for folder, folder_files in files_by_folder.items():
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    all_medium_check(folder_files)
            except Exception as e:
                report.errors.append(f'[medium] {folder}: {e}')
                continue
            batch_label = f'{folder} (batch: {len(folder_files)} файлов)'
            report.findings.extend(
                _parse_findings_from_output(buf.getvalue(), 'medium', batch_label)
            )

    if 'hard' in levels:
        for folder, folder_files in files_by_folder.items():
            buf = io.StringIO()
            try:
                with contextlib.redirect_stdout(buf):
                    all_hard_check(folder_files)
            except Exception as e:
                report.errors.append(f'[hard] {folder}: {e}')
                continue
            # Hard_Check.py сейчас — набор заглушек без реального анализа
            # файлов (см. docstring модуля), поэтому findings из него не
            # извлекаются, чтобы не выдавать вымышленные результаты.
            report.errors.append(
                f'[hard] {folder}: hard-проверки пока заглушки, '
                f'реальные findings не извлекались'
            )

    return report


def audit_easy(path: str = '.') -> AuditReport:
    """Удобная обёртка: только easy-проверки."""
    return audit_project(path, levels=['easy'])


def audit_medium(path: str = '.') -> AuditReport:
    """Удобная обёртка: только medium-проверки."""
    return audit_project(path, levels=['medium'])


def audit_hard(path: str = '.') -> AuditReport:
    """Удобная обёртка: только hard-проверки."""
    return audit_project(path, levels=['hard'])


# ==================== CLI ====================

def build_parser() -> argparse.ArgumentParser:
    """Строит argparse-парсер для CLI-режима."""
    parser = argparse.ArgumentParser(description='Security Auditor')
    parser.add_argument('--path', default='.', help='Путь к проекту или файлу')
    parser.add_argument(
        '--level', default='easy,medium,hard',
        help='Уровни проверок через запятую: easy,medium,hard',
    )
    parser.add_argument('--json', action='store_true', help='Вывести результат в JSON')
    return parser


def main() -> None:
    """Точка входа CLI."""
    args = build_parser().parse_args()
    levels = [lvl.strip().lower() for lvl in args.level.split(',') if lvl.strip()]

    try:
        report = audit_project(args.path, levels)
    except ValueError as e:
        print(f'❌ {e}', file=sys.stderr)
        sys.exit(2)

    if args.json:
        print(json.dumps(report.to_dict(), ensure_ascii=False, indent=2))
    else:
        print(report.summary())

    sys.exit(1 if report.critical_count > 0 else 0)


if __name__ == '__main__':
    main()


"""
ИНТЕГРАЦИЯ С ВЕБ (FastAPI):

    from fastapi import FastAPI
    from find_file import audit_project

    app = FastAPI()

    @app.post("/api/audit")
    def run_audit(path: str = ".", levels: str = "easy,medium,hard"):
        level_list = levels.split(',')
        report = audit_project(path, level_list)
        return report.to_dict()
"""