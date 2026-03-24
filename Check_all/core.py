from dataclasses import dataclass , field
from typing import List , Optional , Dict , Any , Callable
from enum import Enum
from abc import ABC , abstractmethod



class Severity(Enum):
    """Уровни критичности уязвимостей."""
    CRITICAL = "🔴 Критический"
    HIGH = "🟠 Высокий"
    MEDIUM = "🟡 Средний"
    LOW = "🔵 Низкий"
    INFO = "⚪ Информационный"


@dataclass
class SecurityReport:
    """Структура отчёта о проверке безопасности."""
    rule_name: str
    standard: str
    severity: Severity
    issue_description: str
    risk_consequences: str
    insecure_example: str
    secure_example: str
    remediation_steps: List[str] = field(default_factory=list)
    check_id: str = ""
    files_checked: List[str] = field(default_factory=list)

    def print_report(self) -> None:
        """Выводит форматированный отчёт в консоль."""
        print(f"\n{'=' * 70}")
        print(f"🔍 ПРОВЕРКА: {self.rule_name}")
        if self.check_id:
            print(f"📝 ID: {self.check_id}")
        print(f"📋 Стандарт: {self.standard}")
        print(f"⚠️  Критичность: {self.severity.value}")
        print(f"{'=' * 70}")

        print(f"\n❌ ПРОБЛЕМА:\n{self.issue_description}")
        print(f"\n⚠️  РИСКИ И ПОСЛЕДСТВИЯ:\n{self.risk_consequences}")

        print(f"\n🔴 НЕБЕЗОПАСНАЯ КОНФИГУРАЦИЯ:")
        print(f"```yaml\n{self.insecure_example}\n```")

        print(f"\n🟢 РЕКОМЕНДУЕМАЯ КОНФИГУРАЦИЯ:")
        print(f"```yaml\n{self.secure_example}\n```")

        if self.remediation_steps:
            print(f"\n🛠️  ШАГИ ПО ИСПРАВЛЕНИЮ:")
            for i , step in enumerate(self.remediation_steps , 1):
                print(f"   {i}. {step}")

        if self.files_checked:
            print(f"\n📁 Проверенные файлы: {', '.join(self.files_checked)}")

        print(f"\n{'=' * 70}\n")

    def to_dict(self) -> Dict[str , Any]:
        """Возвращает отчёт в виде словаря."""
        return {
            "check_id": self.check_id ,
            "rule_name": self.rule_name ,
            "standard": self.standard ,
            "severity": self.severity.name ,
            "severity_display": self.severity.value ,
            "issue": self.issue_description ,
            "risk": self.risk_consequences ,
            "insecure_config": self.insecure_example ,
            "secure_config": self.secure_example ,
            "remediation": self.remediation_steps ,
            "files_checked": self.files_checked
        }


class BaseCheck(ABC):
    """Базовый класс для всех проверок безопасности."""

    # Переопределяется в наследниках
    RULE_NAME: str = ""
    STANDARD: str = ""
    SEVERITY: Severity = Severity.MEDIUM
    CHECK_ID: str = ""

    def __init__(self , path: str = ""):
        self.path = path
        self.files_checked: List[str] = []

    @abstractmethod
    def check(self) -> SecurityReport:
        """Выполняет проверку и возвращает отчёт."""
        pass

    def _create_report(
            self ,
            issue: str ,
            risk: str ,
            insecure: str ,
            secure: str ,
            remediation: Optional[List[str]] = None
    ) -> SecurityReport:
        """Создаёт отчёт с общими параметрами."""
        return SecurityReport(
            rule_name=self.RULE_NAME ,
            standard=self.STANDARD ,
            severity=self.SEVERITY ,
            check_id=self.CHECK_ID ,
            issue_description=issue ,
            risk_consequences=risk ,
            insecure_example=insecure ,
            secure_example=secure ,
            remediation_steps=remediation or [] ,
            files_checked=self.files_checked
        )

    def __call__(self) -> SecurityReport:
        """Позволяет вызывать проверку как функцию."""
        return self.check()


class CheckRegistry:
    """Реестр всех проверок."""

    _checks: Dict[str , Callable] = {}

    @classmethod
    def register(cls , check_class: type) -> type:
        """Декоратор для регистрации проверки."""
        if hasattr(check_class , 'CHECK_ID') and check_class.CHECK_ID:
            cls._checks[check_class.CHECK_ID] = check_class
        # ❌ Уберите эту строку - она создаёт дубликаты!
        # cls._checks[check_class.__name__] = check_class
        return check_class

    @classmethod
    def get_check(cls , name: str) -> Optional[type]:
        """Получить проверку по имени или ID."""
        return cls._checks.get(name)

    @classmethod
    def get_all_checks(cls) -> dict[str , Callable[... , Any]]:
        """Получить все зарегистрированные проверки."""
        return cls._checks.copy()

    @classmethod
    def get_checks_by_severity(cls , severity: Severity) -> list[Callable[... , Any]]:
        """Получить проверки по уровню критичности."""
        return [
            check for check in cls._checks.values()
            if hasattr(check , 'SEVERITY') and check.SEVERITY == severity
        ]

    @classmethod
    def get_checks_by_level(cls , level: str) -> List[type]:
        ranges = {
            'easy': range(1 , 26) ,
            'medium': range(26 , 51) ,
            'hard': range(51 , 76)
        }
        target = ranges.get(level.lower())
        if not target:
            raise ValueError(f"Unknown level: {level}")

        # ✅ Используем set() для удаления дубликатов классов
        seen = set()
        result = []
        for check in cls._checks.values():
            if check in seen:
                continue
            seen.add(check)

            if hasattr(check , 'CHECK_ID') and \
                    any(f"_{i:02d}" in check.CHECK_ID for i in target):
                result.append(check)

        return result


    @classmethod
    def run_all(cls , level: Optional[str] = None , verbose: bool = True) -> List[SecurityReport]:
        """Запустить все проверки или по уровню."""
        if level:
            checks = cls.get_checks_by_level(level)
        else:
            checks = list(cls._checks.values())

        results = []
        print(f"\n🚀 Запуск проверок{' (' + level + ')' if level else ''}: {len(checks)} шт.\n")

        for check_class in checks:
            try:
                check_instance = check_class()
                report = check_instance.check()

                # ✅ ИСПРАВЛЕНИЕ: добавляем только если уязвимость найдена
                if report is not None:
                    results.append(report)
                    if verbose:
                        report.print_report()
                # else: проверка пройдена успешно - не добавляем в results

            except Exception as e:
                print(f"⚠️  Ошибка в {check_class.__name__}: {e}")

        return results
    @classmethod
    def print_summary(cls , reports: List[SecurityReport]) -> None:
        """Вывести сводную статистику."""
        if not reports:
            print("📊 Нет данных для сводки")
            return

        counts = {sev: 0 for sev in Severity}
        for r in reports:
            if r.severity in counts:
                counts[r.severity] += 1

        print("\n" + "=" * 70)
        print("📊 СВОДКА ПО ПРОВЕРКАМ")
        print("=" * 70)
        for sev in Severity:
            if counts[sev] > 0:
                print(f"{sev.value}: {counts[sev]}")
        print(f"\nВсего проверок: {len(reports)}")
        print("=" * 70 + "\n")