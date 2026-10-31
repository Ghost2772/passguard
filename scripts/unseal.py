import sys

from scripts.common import load_recovery, unseal, vault_http, wait_for_vault


def main() -> None:
    try:
        with vault_http() as client:
            wait_for_vault(client)
            unseal(client, load_recovery())
        print("Vault разблокирован. Секреты и политики сохранены.")
    except (OSError, RuntimeError, ValueError):
        print("Не удалось разблокировать Vault. Проверь контейнер и запись восстановления.", file=sys.stderr)
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
