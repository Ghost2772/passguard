class ScanError(Exception):
    def __init__(self, status: int, code: str, detail: str):
        self.status, self.code, self.detail = status, code, detail
        super().__init__(detail)


ERRORS = {
    "archive_too_large": (413, "ZIP должен быть не больше 5 МиБ"),
    "invalid_archive": (422, "Нужен корректный ZIP без шифрования и специальных файлов"),
    "unsafe_archive_path": (422, "В ZIP есть недопустимые пути или повторяющиеся имена"),
    "excluded_directory": (422, "Удали из ZIP служебные каталоги .git, .local, .venv и node_modules"),
    "archive_limits": (422, "Превышен лимит: 1000 файлов, 1 МиБ на файл или 20 МиБ после распаковки"),
    "no_source_files": (422, "В ZIP нет поддерживаемых текстовых файлов UTF-8"),
    "too_many_findings": (422, "Более 1000 находок; раздели проект на меньшие части"),
    "unsupported_media_type": (415, "Передай ZIP с Content-Type: application/zip"),
    "upload_timeout": (408, "Истекло время загрузки ZIP"),
    "scanner_busy": (429, "Сканер занят; повтори запрос позже"),
    "scanner_timeout": (503, "Истекло время проверки; раздели проект на меньшие части"),
    "scanner_unavailable": (503, "Сканер недоступен; результат проверки не получен"),
}


def failure(code: str) -> ScanError:
    status, detail = ERRORS[code]
    return ScanError(status, code, detail)
